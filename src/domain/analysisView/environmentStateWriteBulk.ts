import type { JsonValue } from "../jsonValue.js";
import {
  at,
  isObject,
  locateItem,
  scalarText,
  segmentsOf,
} from "./environmentStateRules.js";
import {
  bulkCollectionOf,
  namedEntities,
  type NamedEntity,
} from "./environmentStateWriteAddress.js";
import { itemTarget } from "./environmentStateWriteChecks.js";
import { sameQuery } from "./environmentStateWriteStamps.js";
import { deleteEntity } from "./environmentStateWriteDelete.js";
import {
  built,
  fail,
  refuse,
  updateEntity,
  UNKNOWN,
  type EffectContext,
  type EffectResult,
  type WriteDraft,
  type WriteStep,
} from "./environmentStateWriteEffects.js";
import type { WriteResponse } from "./environmentStateWriteRules.js";

/** Whether any scalar in a body passes the test. */
const holds = (
  body: JsonValue | undefined,
  test: (scalar: JsonValue) => boolean,
): boolean => {
  const pending: JsonValue[] = body === undefined ? [] : [body];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    if (Array.isArray(next)) for (const child of next) pending.push(child);
    else if (isObject(next))
      for (const child of Object.values(next)) pending.push(child);
    else if (test(next)) return true;
  }
  return false;
};

/**
 * Whether serving can answer a bulk call with this response for any ids: no body, one that names
 * none of them and counts nothing it wrote, or an array with one element per named entity, each
 * showing its id where the first does.
 */
export const bulkResponseFits = (
  response: WriteResponse,
  body: JsonValue | undefined,
  named: readonly NamedEntity[],
): boolean => {
  if (response.shape === "empty") return true;
  const ids = new Set(named.map(({ id }) => id));
  if (response.shape === "recorded")
    return !holds(
      body,
      (scalar) => ids.has(scalarText(scalar) ?? "") || scalar === named.length,
    );
  if (response.pointer !== "/0" || !Array.isArray(body)) return false;
  return (
    body.length === named.length &&
    named.every(({ id }, index) => {
      const element = body[index];
      if (response.shape === "identity") return scalarText(element) === id;
      const located =
        element === undefined ? undefined : locateItem(element, id);
      return located?.pointer === "" && isObject(at(element!, ""));
    })
  );
};

/** Apply a recorded bulk call to each entity its body names; one it names without holding leaves the call unmodelled there. */
export const applyBulk = (
  context: EffectContext,
  draft: WriteDraft,
  step: WriteStep,
): EffectResult[] => {
  const type = draft.plan.target!;
  const { address } = draft.plan;
  const body = context.io.requestBody(step.record.ordinal);
  const named =
    address === undefined || address.by === "action"
      ? undefined
      : namedEntities(address, body, context.idField(type));
  // A call with another query than the exemplar's may do something else, as serving refuses it.
  if (
    built(draft) &&
    !sameQuery(
      context.io.queryOf(draft.plan.exemplar_ordinal ?? -1),
      step.record.query,
    )
  )
    return [UNKNOWN];
  if (named === undefined) {
    fail(draft, step, "body-unusable");
    return [UNKNOWN];
  }
  const collection = `/${bulkCollectionOf(type, segmentsOf(step.record.path), (text) => text).join("/")}`;
  const wasBuilt = built(draft);
  const results = named.map(({ id, body: members }) => {
    const target = itemTarget(context.state, type, {
      path: `${collection}/${encodeURIComponent(id)}`,
    });
    return draft.plan.effect === "delete"
      ? deleteEntity(context, draft, step, target)
      : updateEntity(context, draft, step, { ...target, body: members });
  });
  // The plan's response is the exemplar's; serving answers any ids with it only in a shape it can render for them.
  const { response } = draft.plan;
  if (
    !wasBuilt &&
    response !== null &&
    !context.io.withBody(step.record.ordinal, (recorded) =>
      bulkResponseFits(response, recorded, named),
    )
  )
    refuse(draft, step, "body-unusable");
  return results;
};
