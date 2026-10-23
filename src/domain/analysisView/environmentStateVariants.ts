import { compareUnicodeCodePoints as compare } from "../unicodeCodePointOrder.js";
import { ENTRY_BYTES, textBytes } from "./webNetworkRouteTemplates.js";
import type { LateLine, StatePlan } from "./environmentStateGate.js";
import type { ObservedEntity } from "./environmentStateMerge.js";
import {
  isProjectionParameter,
  projectsFields,
  type ReplayKey,
  type StateItemView,
  type StateListView,
  type StateRecordFacts,
} from "./environmentStateRules.js";

/** Query names that page a list rather than choose how it shows its entities. */
const PAGING = new Set([
  "limit",
  "offset",
  "page",
  "per_page",
  "perpage",
  "page_size",
  "pagesize",
  "size",
  "start",
  "_start",
  "_end",
  "cursor",
  "pagenumber",
  "pageindex",
  "skip",
  "take",
  "top",
  "$top",
  "$skip",
]);

/** What one recorded line's objects showed: each entity's member names, and the members any and every object carried. */
export interface LineShape {
  readonly entities: ReadonlyMap<string, string>;
  readonly carried: ReadonlySet<string>;
  readonly common: ReadonlySet<string> | undefined;
}

/** Each name a query names, with every value it took. */
export const queryValues = (
  query: string | null | undefined,
): Map<string, string[]> => {
  const values = new Map<string, string[]>();
  for (const [name, value] of new URLSearchParams(query ?? ""))
    values.set(name, [...(values.get(name) ?? []), value]);
  return values;
};

/** Whether a query names a parameter that may change how a line shows its entities, paging and field selections aside. */
export const shapesOtherwise = (query: string | null | undefined): boolean =>
  shapingNames(query).some((name) => !isProjectionParameter(name));

/** The query names that may change how a line shows its entities: all but paging. */
const shapingNames = (query: string | null | undefined): string[] =>
  [...queryValues(query).keys()].filter(
    (name) => !PAGING.has(name.toLowerCase()),
  );

/** The shape each observed recording showed of its entities, by ordinal, each part counted against the budget before it is kept. */
export const lineShapes = (
  entities: Iterable<ObservedEntity>,
  retain: (bytes: number) => void,
): Map<number, LineShape> => {
  const shapes = new Map<
    number,
    {
      entities: Map<string, string>;
      carried: Set<string>;
      common: Set<string> | undefined;
    }
  >();
  retain(ENTRY_BYTES);
  for (const entity of entities)
    for (const observation of entity.observations) {
      const members = Object.keys(observation.object);
      let shape = shapes.get(observation.ordinal);
      if (shape === undefined) {
        // The shape's own entry and containers, with room for the members every object carries.
        retain(ENTRY_BYTES * (4 + members.length));
        shape = { entities: new Map(), carried: new Set(), common: undefined };
        shapes.set(observation.ordinal, shape);
      }
      const key = JSON.stringify([entity.type, entity.collection, entity.id]);
      // A JSON array, since a member name may hold any separator.
      const signature = JSON.stringify([...members].sort(compare));
      if (!shape.entities.has(key))
        retain(ENTRY_BYTES + textBytes(key.length + signature.length));
      shape.entities.set(key, signature);
      for (const member of members)
        if (!shape.carried.has(member)) {
          retain(ENTRY_BYTES);
          shape.carried.add(member);
        }
      shape.common =
        shape.common === undefined
          ? new Set(members)
          : new Set(members.filter((member) => shape!.common!.has(member)));
    }
  return shapes;
};

const EMPTY: LineShape = {
  entities: new Map(),
  carried: new Set(),
  common: undefined,
};

/** Line pairs and entity lookups the variant pass may make; a plan whose lines need more keeps every line checked. */
const VARIANT_WORK_LIMIT = 1 << 24;

/** Whether two lines show a shared entity with different members. */
const conflicts = (left: LineShape, right: LineShape): boolean =>
  [...left.entities].some(
    ([key, members]) =>
      right.entities.has(key) && right.entities.get(key) !== members,
  );

/** What lines compared later are compared with: the shaping parameter names they named, the members their objects carried, and those every one carried. */
interface LineTotals {
  readonly names: Set<string>;
  readonly carried: Set<string>;
  common: Set<string> | undefined;
}

/** Totals over no lines yet. */
const noLines = (): LineTotals => ({
  names: new Set(),
  carried: new Set(),
  common: undefined,
});

/** Count one more line into the totals. */
const addLine = (
  totals: LineTotals,
  query: string | null | undefined,
  shape: Pick<LineShape, "carried" | "common">,
): void => {
  for (const name of shapingNames(query)) totals.names.add(name);
  for (const member of shape.carried) totals.carried.add(member);
  const { common } = shape;
  if (common !== undefined)
    totals.common =
      totals.common === undefined
        ? new Set(common)
        : new Set([...totals.common].filter((member) => common.has(member)));
};

/** Whether a query names a shaping parameter, paging aside, that none of the counted lines named. */
const namesNewParameter = (
  query: string | null | undefined,
  totals: LineTotals,
): boolean => shapingNames(query).some((name) => !totals.names.has(name));

/** Whether a line's objects carry a member the counted lines' never did, or lack one theirs always carried. */
const showsOtherMembers = (
  shape: Pick<LineShape, "carried" | "common">,
  totals: LineTotals,
): boolean => {
  const { common } = shape;
  return (
    [...shape.carried].some((member) => !totals.carried.has(member)) ||
    (common !== undefined &&
      totals.common !== undefined &&
      [...totals.common].some((member) => !common.has(member)))
  );
};

/** The base lines so far, with their totals. */
interface BaseLines extends LineTotals {
  readonly lines: StateRecordFacts[];
}

/**
 * The latest lines that show the plan's entities in another representation than its base lines, as
 * an expanding or reducing query does; none when comparing every pair of lines would exceed the work limit.
 */
export const variantLines = (
  latest: readonly StateRecordFacts[],
  shapeOf: (record: StateRecordFacts) => LineShape | undefined,
): StateRecordFacts[] => {
  if (latest.length < 2) return [];
  const shapes = new Map(
    latest.map((record) => [record, shapeOf(record) ?? EMPTY]),
  );
  const entities = [...shapes.values()].reduce(
    (sum, line) => sum + line.entities.size,
    0,
  );
  // Each line is compared with every other, pair by pair and entity by entity.
  if (latest.length * (latest.length + entities) > VARIANT_WORK_LIMIT)
    return [];
  const shape = (record: StateRecordFacts): LineShape => shapes.get(record)!;
  const ranks = new Map(
    latest.map((record) => {
      const names = shapingNames(record.query).length;
      const agreeing = latest.filter(
        (other) => other !== record && !conflicts(shape(record), shape(other)),
      ).length;
      return [
        record,
        [
          names === 0 ? 0 : 1,
          projectsFields(record.query ?? undefined) ? 1 : 0,
          -agreeing,
          names,
          shape(record).carried.size,
        ],
      ];
    }),
  );
  // Base lines first: no shaping query, then no projection, then the line most others agree with.
  const ordered = [...latest].sort((left, right) => {
    const [a, b] = [ranks.get(left)!, ranks.get(right)!];
    const differs = a.findIndex((value, index) => value !== b[index]);
    return differs === -1 ? 0 : a[differs]! - b[differs]!;
  });
  const base: BaseLines = { ...noLines(), lines: [] };
  const variants: StateRecordFacts[] = [];
  for (const record of ordered) {
    if (base.lines.length > 0 && isVariant(record, base, shape))
      variants.push(record);
    else {
      base.lines.push(record);
      addLine(base, record.query, shape(record));
    }
  }
  return variants;
};

/** Whether a line shows a base line's entity with other members, or names a new shaping parameter while its objects carry or lack members the base lines do not. */
const isVariant = (
  record: StateRecordFacts,
  base: BaseLines,
  shape: (record: StateRecordFacts) => LineShape,
): boolean => {
  const mine = shape(record);
  if (base.lines.some((line) => conflicts(mine, shape(line)))) return true;
  return namesNewParameter(record.query, base) && showsOtherMembers(mine, base);
};

/** The keys that tell replayed lines from base lines: a parameter or value only replayed lines give, or a parameter every base line names that one leaves out. */
export const replayKeys = (
  base: readonly (string | null | undefined)[],
  replayed: readonly (string | null | undefined)[],
  retain: (bytes: number) => void = () => undefined,
): ReplayKey[] => {
  const baseValues = base.map(queryValues);
  const named = new Set(baseValues.flatMap((values) => [...values.keys()]));
  const everywhere = [...named].filter(
    (name) =>
      !PAGING.has(name.toLowerCase()) &&
      baseValues.every((values) => values.has(name)),
  );
  const keys = new Map<string, ReplayKey>();
  const add = (key: ReplayKey): void => {
    const id = JSON.stringify([
      key.name,
      key.value ?? null,
      key.absent ?? false,
    ]);
    if (keys.has(id)) return;
    // Each key is kept with its text, so it is charged before it is.
    retain(ENTRY_BYTES * 2 + textBytes(id.length));
    keys.set(id, key);
  };
  for (const query of replayed) {
    const values = queryValues(query);
    for (const [name, given] of values) {
      if (PAGING.has(name.toLowerCase())) continue;
      const unseen = given.filter(
        (value) =>
          !baseValues.some(
            (other) => other.get(name)?.includes(value) === true,
          ),
      );
      if (!named.has(name)) add({ name });
      else for (const value of unseen) add({ name, value });
    }
    for (const name of everywhere)
      if (!values.has(name)) add({ name, absent: true });
  }
  return [...keys.values()].sort(
    (left, right) =>
      compare(left.name, right.name) ||
      compare(left.value ?? "", right.value ?? "") ||
      Number(left.absent ?? false) - Number(right.absent ?? false),
  );
};

/** Whether a call's query names a replay key: the parameter, the parameter with that value, or leaves out an absent key's parameter. */
const matchesReplayKey = (
  keys: readonly ReplayKey[],
  call: ReadonlyMap<string, readonly string[]>,
): boolean =>
  keys.some((key) =>
    key.absent === true
      ? !call.has(key.name)
      : key.value === undefined
        ? call.has(key.name)
        : call.get(key.name)?.includes(key.value) === true,
  );

/** Whether a call asks for a selection of fields the checked lines do not show exactly: a projection value a replayed line gave, or one no checked line gave other than `*`. */
const selectsOtherFields = (
  call: ReadonlyMap<string, readonly string[]>,
  checked: readonly (string | null | undefined)[],
  replayed: readonly (string | null | undefined)[],
): boolean => {
  const [base, other] = [checked.map(queryValues), replayed.map(queryValues)];
  const gave = (lines: Map<string, string[]>[], name: string, value: string) =>
    lines.some((values) => values.get(name)?.includes(value) === true);
  return [...call].some(
    ([name, values]) =>
      isProjectionParameter(name) &&
      values.some(
        (value) =>
          gave(other, name, value) ||
          (value !== "*" && !gave(base, name, value)),
      ),
  );
};

/** Why serving replays a read call rather than answering it from the state (`projection` for some fields only, `variant` for another representation); the gate skips the same reads. */
export const replayReason = (
  view: Pick<
    StateItemView | StateListView,
    | "checked_record_ordinals"
    | "projected_record_ordinals"
    | "projected_query_keys"
  >,
  call: ReadonlyMap<string, readonly string[]>,
  queryOf: (ordinal: number) => string | null | undefined,
): "projection" | "variant" | undefined => {
  if (view.projected_record_ordinals === undefined) return undefined;
  // A field selection is tested on its own: a variant key cannot name every value the checked lines do not show.
  if (
    [...call.keys()].some(isProjectionParameter) &&
    selectsOtherFields(
      call,
      view.checked_record_ordinals.map(queryOf),
      view.projected_record_ordinals.map(queryOf),
    )
  )
    return "projection";
  const matched = (view.projected_query_keys ?? []).filter(
    (key) =>
      (key.absent === true || !isProjectionParameter(key.name)) &&
      matchesReplayKey([key], call),
  );
  if (matched.length === 0) return undefined;
  return matched.some((key) => isProjectionParameter(key.name))
    ? "projection"
    : "variant";
};

const requestLine = (record: StateRecordFacts): string =>
  record.path + (record.query ?? "");

/** The plan with the variants a key picks out moved to its replayed reads and their recordings dropped, or undefined when it replays nothing. */
export const withoutVariants = (
  plan: StatePlan,
  facts: {
    readonly shapeOf: (record: StateRecordFacts) => LineShape | undefined;
    readonly queryOf: (ordinal: number) => string | null | undefined;
    readonly position: (ordinal: number) => number;
    readonly retain: (bytes: number) => void;
  },
):
  | { readonly plan: StatePlan; readonly dropped: ReadonlySet<number> }
  | undefined => {
  const found = variantLines(plan.latest, facts.shapeOf);
  const unkeyed = plan.latest.filter((record) => !found.includes(record));
  const variants = found.filter(
    (record) =>
      replayKeys(
        unkeyed.map((line) => line.query),
        [record.query],
      ).length > 0,
  );
  const lines = new Set(variants.map(requestLine));
  const latest = plan.latest.filter(
    (record) => !lines.has(requestLine(record)),
  );
  const projected = [
    ...(plan.projected ?? []),
    ...lateReplays(plan.late ?? [], latest, facts.shapeOf),
  ];
  if (variants.length === 0 && projected.length === 0) return undefined;
  const replayed = [
    ...projected,
    ...variants.map((record) => record.ordinal),
  ].sort((left, right) => facts.position(left) - facts.position(right));
  const dropped = new Set(
    plan.recordings
      .filter((record) => lines.has(requestLine(record)))
      .map((record) => record.ordinal),
  );
  return {
    plan: {
      ...plan,
      recordings: plan.recordings.filter(
        (record) => !dropped.has(record.ordinal),
      ),
      latest,
      projected: replayed,
      projectedKeys: replayKeys(
        latest.map((record) => record.query),
        replayed.map(facts.queryOf),
        facts.retain,
      ),
    },
    dropped,
  };
};

/**
 * The later item lines serving replays, decided against the lines left: a selection of some fields
 * that leaves out members they always show, or a line naming a shaping parameter none of them names
 * while its object carries or lacks members theirs do not.
 */
const lateReplays = (
  late: readonly LateLine[],
  base: readonly StateRecordFacts[],
  shapeOf: (record: StateRecordFacts) => LineShape | undefined,
): number[] => {
  if (late.length === 0) return [];
  const totals = noLines();
  for (const record of base)
    addLine(totals, record.query, shapeOf(record) ?? EMPTY);
  return late.flatMap(({ record, members, projecting }) =>
    (projecting ||
      shapingNames(record.query).some(
        (name) => !isProjectionParameter(name) && !totals.names.has(name),
      )) &&
    showsOtherMembers({ carried: members, common: members }, totals)
      ? [record.ordinal]
      : [],
  );
};

/** Forget the observations of dropped recordings, and entities only they showed; an entity is first sighted where its kept observations show it first. */
export const dropObservations = (
  entities: Map<string, ObservedEntity>,
  dropped: ReadonlySet<number>,
): void => {
  for (const [key, entity] of entities) {
    const kept = entity.observations.filter(
      (observation) => !dropped.has(observation.ordinal),
    );
    if (kept.length === entity.observations.length) continue;
    if (kept.length === 0) {
      entities.delete(key);
      continue;
    }
    const first = kept.reduce((earliest, observation) =>
      observation.position < earliest.position ||
      (observation.position === earliest.position &&
        observation.index < earliest.index)
        ? observation
        : earliest,
    );
    entities.set(key, {
      ...entity,
      order: [first.position, first.index],
      observations: kept,
    });
  }
};
