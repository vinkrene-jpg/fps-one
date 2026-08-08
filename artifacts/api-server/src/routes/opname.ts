import { Router } from "express";
import { db } from "@workspace/db";
import {
  opnamesTable,
  opnameItemsTable,
  opnameFotosTable,
  gebouwenTable,
  verdiepingenTable,
  gebruikersTable,
  voorzieningenTable,
} from "@workspace/db";
import { eq, and, desc, sql } from "drizzle-orm";
import { requireAuth, requireBevoegdheid, requireEnigeBevoegdheid } from "../middlewares/auth.js";
import { ObjectStorageService } from "../lib/objectStorage.js";

function gebouwAfkorting(naam: string): string {
  const woorden = (naam ?? "").trim().split(/\s+/).filter(Boolean);
  let afk = "";
  if (woorden.length >= 2) {
    afk = woorden.map((w) => w[0]).join("");
  } else if (woorden.length === 1) {
    afk = woorden[0];
  }
  afk = afk.replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(0, 3);
  return afk || "GEB";
}

async function volgendSpotnummer(gebouwId: number): Promise<string> {
  const gebouw = await db
    .select({ naam: gebouwenTable.naam })
    .from(gebouwenTable)
    .where(eq(gebouwenTable.id, gebouwId))
    .then((r) => r[0]);
  const afk = gebouwAfkorting(gebouw?.naam ?? "");
  const prefix = `${afk}-`;
  const bestaande = await db
    .select({ objectnummer: voorzieningenTable.objectnummer })
    .from(voorzieningenTable)
    .where(eq(voorzieningenTable.gebouwId, gebouwId));
  let hoogste = 0;
  for (const r of bestaande) {
    if (!r.objectnummer?.startsWith(prefix)) continue;
    const m = r.objectnummer.match(/(\d+)$/);
    if (m) { const n = parseInt(m[1], 10); if (n > hoogste) hoogste = n; }
  }
  let n = hoogste + 1;
  while (true) {
    const kandidaat = `${prefix}${n}`;
    const bestaat = await db
      .select({ id: voorzieningenTable.id })
      .from(voorzieningenTable)
      .where(eq(voorzieningenTable.objectnummer, kandidaat))
      .then((r) => r[0]);
    if (!bestaat) return kandidaat;
    n++;
  }
}

const router = Router();
const objectStorage = new ObjectStorageService();

// ─── helpers ──────────────────────────────────────────────────────────────────

function fotoUrl(objectPath: string): string {
  return `/api/storage/objects/${encodeURIComponent(objectPath.replace(/^\/objects\//, ""))}`;
}

async function opnameMetItems(id: number) {
  const [opname] = await db
    .select({
      id: opnamesTable.id,
      // NUMMER_01: M-nummer uit seq_nummer_m (systeem-uitgegeven)
      nummer: opnamesTable.nummer,
      gebouw_id: opnamesTable.gebouwId,
      gebouw_naam: gebouwenTable.naam,
      naam: opnamesTable.naam,
      datum: opnamesTable.datum,
      status: opnamesTable.status,
      notities: opnamesTable.notities,
      aangemaakt_door_naam: gebruikersTable.naam,
      aangemaakt_op: opnamesTable.aangemaaktOp,
      bijgewerkt_op: opnamesTable.bijgewerktOp,
    })
    .from(opnamesTable)
    .leftJoin(gebouwenTable, eq(opnamesTable.gebouwId, gebouwenTable.id))
    .leftJoin(gebruikersTable, eq(opnamesTable.aangemaaktDoorId, gebruikersTable.id))
    .where(eq(opnamesTable.id, id))
    .limit(1);

  if (!opname) return null;

  const items = await db
    .select({
      id: opnameItemsTable.id,
      opname_id: opnameItemsTable.opnameId,
      spot_type: opnameItemsTable.spotType,
      ruimte: opnameItemsTable.ruimte,
      verdieping_id: opnameItemsTable.verdiepingId,
      verdieping_naam: verdiepingenTable.naam,
      beschrijving: opnameItemsTable.beschrijving,
      actie: opnameItemsTable.actie,
      bereikbaarheid: opnameItemsTable.bereikbaarheid,
      aantal: opnameItemsTable.aantal,
      afmetingen: opnameItemsTable.afmetingen,
      prioriteit: opnameItemsTable.prioriteit,
      notities: opnameItemsTable.notities,
      afgerond: opnameItemsTable.afgerond,
      tekening_x: opnameItemsTable.tekeningX,
      tekening_y: opnameItemsTable.tekeningY,
      aangemaakt_op: opnameItemsTable.aangemaaktOp,
      bijgewerkt_op: opnameItemsTable.bijgewerktOp,
    })
    .from(opnameItemsTable)
    .leftJoin(verdiepingenTable, eq(opnameItemsTable.verdiepingId, verdiepingenTable.id))
    .where(eq(opnameItemsTable.opnameId, id))
    .orderBy(opnameItemsTable.id);

  const itemsMetFotos = await Promise.all(
    items.map(async (item) => {
      const fotos = await db
        .select()
        .from(opnameFotosTable)
        .where(eq(opnameFotosTable.itemId, item.id))
        .orderBy(opnameFotosTable.id);

      return {
        ...item,
        fotos: fotos.map((f) => ({
          id: f.id,
          item_id: f.itemId,
          object_path: f.objectPath,
          url: fotoUrl(f.objectPath),
          bijschrift: f.bijschrift,
          aangemaakt_op: f.aangemaaktOp,
        })),
      };
    }),
  );

  return { ...opname, items: itemsMetFotos };
}

// ─── GET /opname ──────────────────────────────────────────────────────────────

router.get("/opname", requireAuth, requireEnigeBevoegdheid([["gebouwen", 1], ["voorzieningen", 1]]), async (req, res): Promise<void> => {
  const gebouwId = req.query.gebouw_id ? Number(req.query.gebouw_id as string) : null;
  const status = req.query.status as string | undefined;

  const rows = await db
    .select({
      id: opnamesTable.id,
      // NUMMER_01: M-nummer uit seq_nummer_m (systeem-uitgegeven)
      nummer: opnamesTable.nummer,
      gebouw_id: opnamesTable.gebouwId,
      gebouw_naam: gebouwenTable.naam,
      naam: opnamesTable.naam,
      datum: opnamesTable.datum,
      status: opnamesTable.status,
      notities: opnamesTable.notities,
      aangemaakt_door_naam: gebruikersTable.naam,
      aangemaakt_op: opnamesTable.aangemaaktOp,
      bijgewerkt_op: opnamesTable.bijgewerktOp,
      aantal_items: sql<number>`(
        SELECT COUNT(*)::int FROM opname_items WHERE opname_id = ${opnamesTable.id}
      )`,
    })
    .from(opnamesTable)
    .leftJoin(gebouwenTable, eq(opnamesTable.gebouwId, gebouwenTable.id))
    .leftJoin(gebruikersTable, eq(opnamesTable.aangemaaktDoorId, gebruikersTable.id))
    .where(
      and(
        gebouwId != null ? eq(opnamesTable.gebouwId, gebouwId) : undefined,
        status ? eq(opnamesTable.status, status) : undefined,
      ),
    )
    .orderBy(desc(opnamesTable.bijgewerktOp));

  res.json(rows);
});

// ─── POST /opname ─────────────────────────────────────────────────────────────

router.post("/opname", requireAuth, requireBevoegdheid("voorzieningen", 3), async (req, res): Promise<void> => {
  const { gebouw_id, naam, datum, notities } = req.body as {
    gebouw_id?: number | null;
    naam: string;
    datum: string;
    notities?: string;
  };

  if (!naam || !datum) {
    res.status(400).json({ fout: "naam en datum zijn verplicht" });
    return;
  }

  const [nieuw] = await db
    .insert(opnamesTable)
    .values({
      gebouwId: gebouw_id ?? null,
      naam,
      datum,
      notities: notities ?? null,
      aangemaaktDoorId: req.session.userId ?? null,
    })
    .returning();

  const volledig = await opnameMetItems(nieuw.id);
  res.status(201).json(volledig);
});

// ─── GET /opname/plattegrond-items ────────────────────────────────────────────
// Geeft alle opname-items terug die een tekening-positie hebben op een verdieping.
// Gebruikt door de plattegrond-laag in de uitvoeringstekening.
// LET OP: dit blok moet VÓÓR de wildcard-route /opname/:id blijven staan, anders
// matcht Express "plattegrond-items" als :id en faalt dit endpoint.

router.get("/opname/plattegrond-items", requireAuth, requireEnigeBevoegdheid([["gebouwen", 1], ["voorzieningen", 1]]), async (req, res): Promise<void> => {
  const verdiepingId = Number(req.query.verdieping_id);
  if (!verdiepingId || isNaN(verdiepingId)) {
    res.status(400).json({ fout: "verdieping_id is verplicht" });
    return;
  }

  const items = await db
    .select({
      id: opnameItemsTable.id,
      opname_id: opnameItemsTable.opnameId,
      spot_type: opnameItemsTable.spotType,
      ruimte: opnameItemsTable.ruimte,
      verdieping_id: opnameItemsTable.verdiepingId,
      verdieping_naam: verdiepingenTable.naam,
      beschrijving: opnameItemsTable.beschrijving,
      actie: opnameItemsTable.actie,
      bereikbaarheid: opnameItemsTable.bereikbaarheid,
      aantal: opnameItemsTable.aantal,
      afmetingen: opnameItemsTable.afmetingen,
      prioriteit: opnameItemsTable.prioriteit,
      notities: opnameItemsTable.notities,
      afgerond: opnameItemsTable.afgerond,
      tekening_x: opnameItemsTable.tekeningX,
      tekening_y: opnameItemsTable.tekeningY,
      aangemaakt_op: opnameItemsTable.aangemaaktOp,
      bijgewerkt_op: opnameItemsTable.bijgewerktOp,
    })
    .from(opnameItemsTable)
    .leftJoin(verdiepingenTable, eq(opnameItemsTable.verdiepingId, verdiepingenTable.id))
    .where(
      and(
        eq(opnameItemsTable.verdiepingId, verdiepingId),
        sql`${opnameItemsTable.tekeningX} IS NOT NULL`,
      ),
    )
    .orderBy(opnameItemsTable.id);

  const itemsMetFotos = await Promise.all(
    items.map(async (item) => {
      const fotos = await db
        .select()
        .from(opnameFotosTable)
        .where(eq(opnameFotosTable.itemId, item.id))
        .orderBy(opnameFotosTable.id);
      return {
        ...item,
        fotos: fotos.map((f) => ({
          id: f.id,
          item_id: f.itemId,
          object_path: f.objectPath,
          url: fotoUrl(f.objectPath),
          bijschrift: f.bijschrift,
          aangemaakt_op: f.aangemaaktOp,
        })),
      };
    }),
  );

  res.json(itemsMetFotos);
});

// ─── GET /opname/:id ──────────────────────────────────────────────────────────

router.get("/opname/:id", requireAuth, requireEnigeBevoegdheid([["gebouwen", 1], ["voorzieningen", 1]]), async (req, res): Promise<void> => {
  const id = Number(req.params.id);
  const opname = await opnameMetItems(id);
  if (!opname) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  res.json(opname);
});

// ─── PATCH /opname/:id ────────────────────────────────────────────────────────

router.patch("/opname/:id", requireAuth, requireBevoegdheid("voorzieningen", 2), async (req, res): Promise<void> => {
  const id = Number(req.params.id);
  const { naam, datum, notities, status } = req.body as {
    naam?: string;
    datum?: string;
    notities?: string | null;
    status?: string;
  };

  const updates: Record<string, unknown> = { bijgewerktOp: new Date() };
  if (naam !== undefined) updates.naam = naam;
  if (datum !== undefined) updates.datum = datum;
  if (notities !== undefined) updates.notities = notities;
  if (status !== undefined) updates.status = status;

  const [updated] = await db
    .update(opnamesTable)
    .set(updates)
    .where(eq(opnamesTable.id, id))
    .returning();

  if (!updated) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  const volledig = await opnameMetItems(id);
  res.json(volledig);
});

// ─── POST /opname/:id/definitief ──────────────────────────────────────────────

router.post("/opname/:id/definitief", requireAuth, requireBevoegdheid("voorzieningen", 2), async (req, res): Promise<void> => {
  const id = Number(req.params.id);
  const [bestaand] = await db
    .select({ id: opnamesTable.id, status: opnamesTable.status })
    .from(opnamesTable)
    .where(eq(opnamesTable.id, id))
    .limit(1);

  if (!bestaand) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  if (bestaand.status === "definitief") { res.status(409).json({ fout: "Al definitief" }); return; }

  await db
    .update(opnamesTable)
    .set({ status: "definitief", bijgewerktOp: new Date() })
    .where(eq(opnamesTable.id, id));

  const volledig = await opnameMetItems(id);
  res.json(volledig);
});

// ─── POST /opname/:id/spots-aanmaken ──────────────────────────────────────────

router.post("/opname/:id/spots-aanmaken", requireAuth, requireBevoegdheid("voorzieningen", 3), async (req, res): Promise<void> => {
  const id = Number(req.params.id);
  const opname = await opnameMetItems(id);
  if (!opname) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  if (opname.status !== "definitief") {
    res.status(409).json({ fout: "Opname moet definitief zijn voordat spots aangemaakt kunnen worden" });
    return;
  }
  if (!opname.gebouw_id) {
    res.status(409).json({ fout: "Opname heeft geen gekoppeld gebouw" });
    return;
  }

  const gebouwId = opname.gebouw_id;
  const aangemaakteIds: number[] = [];
  let overgeslagen = 0;
  const gebruikerId = req.session.userId ?? null;

  for (const item of opname.items) {
    if (!item.spot_type) { overgeslagen++; continue; }
    let nummer = await volgendSpotnummer(gebouwId);
    let spot: typeof voorzieningenTable.$inferSelect | undefined;
    for (let poging = 0; poging < 5; poging++) {
      try {
        [spot] = await db
          .insert(voorzieningenTable)
          .values({
            objectnummer: nummer,
            type: item.spot_type,
            status: "concept",
            classificatie: "60",
            gebouwId,
            verdiepingId: item.verdieping_id ?? null,
            ruimte: item.ruimte ?? null,
            opmerkingen: [item.beschrijving, item.notities].filter(Boolean).join(" | ") || null,
            makerMonteurId: gebruikerId,
          })
          .returning();
        break;
      } catch (err) {
        const code = (err as { code?: string })?.code;
        if (code === "23505" && poging < 4) { nummer = await volgendSpotnummer(gebouwId); continue; }
        spot = undefined;
        break;
      }
    }
    if (spot) aangemaakteIds.push(spot.id);
    else overgeslagen++;
  }

  res.json({ aangemaakt: aangemaakteIds.length, overgeslagen, spot_ids: aangemaakteIds });
});

// ─── GET /opname/:id/items ────────────────────────────────────────────────────

router.get("/opname/:id/items", requireAuth, requireEnigeBevoegdheid([["gebouwen", 1], ["voorzieningen", 1]]), async (req, res): Promise<void> => {
  const opnameId = Number(req.params.id);
  const opname = await opnameMetItems(opnameId);
  if (!opname) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  res.json(opname.items);
});

// ─── POST /opname/:id/items ───────────────────────────────────────────────────

router.post("/opname/:id/items", requireAuth, requireBevoegdheid("voorzieningen", 3), async (req, res): Promise<void> => {
  const opnameId = Number(req.params.id);
  const {
    spot_type, ruimte, verdieping_id, beschrijving,
    actie, bereikbaarheid, aantal, afmetingen, prioriteit, notities, afgerond,
  } = req.body as {
    spot_type: string;
    ruimte?: string;
    verdieping_id?: number;
    beschrijving?: string;
    actie?: string;
    bereikbaarheid?: string;
    aantal?: number;
    afmetingen?: string;
    prioriteit?: string;
    notities?: string;
    afgerond?: boolean;
  };

  if (!spot_type) {
    res.status(400).json({ fout: "spot_type is verplicht" });
    return;
  }

  const [bestaand] = await db
    .select({ id: opnamesTable.id })
    .from(opnamesTable)
    .where(eq(opnamesTable.id, opnameId))
    .limit(1);
  if (!bestaand) { res.status(404).json({ fout: "Opname niet gevonden" }); return; }

  const [nieuw] = await db
    .insert(opnameItemsTable)
    .values({
      opnameId,
      spotType: spot_type,
      ruimte: ruimte ?? null,
      verdiepingId: verdieping_id ?? null,
      beschrijving: beschrijving ?? null,
      actie: actie ?? "controleren",
      bereikbaarheid: bereikbaarheid ?? "goed",
      aantal: aantal ?? 1,
      afmetingen: afmetingen ?? null,
      prioriteit: prioriteit ?? "normaal",
      notities: notities ?? null,
      afgerond: afgerond ?? false,
    })
    .returning();

  await db
    .update(opnamesTable)
    .set({ bijgewerktOp: new Date() })
    .where(eq(opnamesTable.id, opnameId));

  const fotos = await db
    .select()
    .from(opnameFotosTable)
    .where(eq(opnameFotosTable.itemId, nieuw.id))
    .orderBy(opnameFotosTable.id);

  res.json({
    ...nieuw,
    fotos: fotos.map((f) => ({
      id: f.id,
      item_id: f.itemId,
      object_path: f.objectPath,
      url: fotoUrl(f.objectPath),
      bijschrift: f.bijschrift,
      aangemaakt_op: f.aangemaaktOp,
    })),
  });
});

// ─── PATCH /opname/items/:itemId ──────────────────────────────────────────────

router.patch("/opname/items/:itemId", requireAuth, requireBevoegdheid("voorzieningen", 2), async (req, res): Promise<void> => {
  const itemId = Number(req.params.itemId);
  const [item] = await db
    .select({ id: opnameItemsTable.id, opnameId: opnameItemsTable.opnameId })
    .from(opnameItemsTable)
    .where(eq(opnameItemsTable.id, itemId))
    .limit(1);

  if (!item) { res.status(404).json({ fout: "Niet gevonden" }); return; }

  const fotos = await db
    .select()
    .from(opnameFotosTable)
    .where(eq(opnameFotosTable.itemId, itemId))
    .orderBy(opnameFotosTable.id);

  res.json({
    ...item,
    fotos: fotos.map((f) => ({
      id: f.id,
      item_id: f.itemId,
      object_path: f.objectPath,
      url: fotoUrl(f.objectPath),
      bijschrift: f.bijschrift,
      aangemaakt_op: f.aangemaaktOp,
    })),
  });
});

// ─── PATCH /opname/items/:itemId ──────────────────────────────────────────────

router.patch("/opname/items/:itemId", requireAuth, requireBevoegdheid("voorzieningen", 2), async (req, res): Promise<void> => {
  const itemId = Number(req.params.itemId);
  const velden = req.body as Record<string, unknown>;

  const toegestaan = [
    "spot_type", "ruimte", "verdieping_id", "beschrijving",
    "actie", "bereikbaarheid", "aantal", "afmetingen", "prioriteit", "notities", "afgerond",
    "tekening_x", "tekening_y",
  ];

  const camelMap: Record<string, string> = {
    spot_type: "spotType",
    verdieping_id: "verdiepingId",
    tekening_x: "tekeningX",
    tekening_y: "tekeningY",
    aangemaakt_op: "aangemaaktOp",
    bijgewerkt_op: "bijgewerktOp",
  };

  const updates: Record<string, unknown> = { bijgewerktOp: new Date() };
  for (const key of toegestaan) {
    if (key in velden) {
      const dbKey = camelMap[key] ?? key;
      updates[dbKey] = velden[key] ?? null;
    }
  }

  const [updated] = await db
    .update(opnameItemsTable)
    .set(updates)
    .where(eq(opnameItemsTable.id, itemId))
    .returning();

  if (!updated) { res.status(404).json({ fout: "Niet gevonden" }); return; }

  await db
    .update(opnamesTable)
    .set({ bijgewerktOp: new Date() })
    .where(eq(opnamesTable.id, updated.opnameId));

  const fotos = await db
    .select()
    .from(opnameFotosTable)
    .where(eq(opnameFotosTable.itemId, itemId))
    .orderBy(opnameFotosTable.id);

  const [verdieping] = updated.verdiepingId
    ? await db
        .select({ naam: verdiepingenTable.naam })
        .from(verdiepingenTable)
        .where(eq(verdiepingenTable.id, updated.verdiepingId))
        .limit(1)
    : [{ naam: null }];

  res.json({
    id: updated.id,
    opname_id: updated.opnameId,
    spot_type: updated.spotType,
    ruimte: updated.ruimte,
    verdieping_id: updated.verdiepingId,
    verdieping_naam: verdieping?.naam ?? null,
    beschrijving: updated.beschrijving,
    actie: updated.actie,
    bereikbaarheid: updated.bereikbaarheid,
    aantal: updated.aantal,
    afmetingen: updated.afmetingen,
    prioriteit: updated.prioriteit,
    notities: updated.notities,
    afgerond: updated.afgerond,
    tekening_x: updated.tekeningX ?? null,
    tekening_y: updated.tekeningY ?? null,
    aangemaakt_op: updated.aangemaaktOp,
    bijgewerkt_op: updated.bijgewerktOp,
    fotos: fotos.map((f) => ({
      id: f.id,
      item_id: f.itemId,
      object_path: f.objectPath,
      url: fotoUrl(f.objectPath),
      bijschrift: f.bijschrift,
      aangemaakt_op: f.aangemaaktOp,
    })),
  });
});

// ─── DELETE /opname/items/:itemId ─────────────────────────────────────────────

router.delete("/opname/items/:itemId", requireAuth, requireBevoegdheid("voorzieningen", 3), async (req, res): Promise<void> => {
  const itemId = Number(req.params.itemId);
  const [deleted] = await db
    .delete(opnameItemsTable)
    .where(eq(opnameItemsTable.id, itemId))
    .returning();
  if (!deleted) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  res.status(204).send();
});

// ─── POST /opname/items/:itemId/fotos ─────────────────────────────────────────

router.post("/opname/items/:itemId/fotos", requireAuth, requireBevoegdheid("voorzieningen", 3), async (req, res): Promise<void> => {
  const itemId = Number(req.params.itemId);
  const { bestandsnaam, content_type, bijschrift } = req.body as {
    bestandsnaam: string;
    content_type: string;
    bijschrift?: string;
  };

  const [item] = await db
    .select({ id: opnameItemsTable.id, opnameId: opnameItemsTable.opnameId })
    .from(opnameItemsTable)
    .where(eq(opnameItemsTable.id, itemId))
    .limit(1);
  if (!item) { res.status(404).json({ fout: "Item niet gevonden" }); return; }

  const [opname] = await db
    .select({ gebouwId: opnamesTable.gebouwId })
    .from(opnamesTable)
    .where(eq(opnamesTable.id, item.opnameId))
    .limit(1);

  void bestandsnaam; void content_type;

  const { uploadURL, objectPath } = await objectStorage.getObjectEntityUploadURL(
    opname?.gebouwId ?? null,
    "foto",
  );

  const [foto] = await db
    .insert(opnameFotosTable)
    .values({ itemId, objectPath, bijschrift: bijschrift ?? null })
    .returning();

  res.status(201).json({
    upload_url: uploadURL,
    foto: {
      id: foto.id,
      item_id: foto.itemId,
      object_path: foto.objectPath,
      url: fotoUrl(foto.objectPath),
      bijschrift: foto.bijschrift,
      aangemaakt_op: foto.aangemaaktOp,
    },
  });
});

// ─── DELETE /opname/fotos/:fotoId ─────────────────────────────────────────────

router.delete("/opname/fotos/:fotoId", requireAuth, requireBevoegdheid("voorzieningen", 3), async (req, res): Promise<void> => {
  const fotoId = Number(req.params.fotoId);
  const [deleted] = await db
    .delete(opnameFotosTable)
    .where(eq(opnameFotosTable.id, fotoId))
    .returning();
  if (!deleted) { res.status(404).json({ fout: "Niet gevonden" }); return; }
  res.status(204).send();
});

export default router;
