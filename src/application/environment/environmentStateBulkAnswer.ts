import {
  bulkCollectionOf,
  namedEntities,
} from "../../domain/analysisView/environmentStateWriteAddress.js";
import {
  updatedEntity,
  updatedFields,
  writtenResponse,
} from "../../domain/analysisView/environmentStateWriteApply.js";
import type {
  FieldRule,
  WriteResponse,
} from "../../domain/analysisView/environmentStateWriteRules.js";
import type {
  JsonObject,
  StateEntity,
} from "../../domain/analysisView/environmentStateRules.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import { callSegments } from "./environmentStateCallLines.js";
import {
  namedEntity,
  refused,
  type StateAnswer,
  type StateServing,
} from "./environmentStateAnswer.js";
import {
  isLoadableValue,
  unloadableMember,
} from "./environmentStateDocument.js";
import {
  generator,
  observedEntity,
  pathValues,
  unloadable,
  writeAnswer,
  type WriteRequest,
} from "./environmentStateWriteAnswer.js";
import { environmentToolArguments } from "./environmentTools.js";

/** Rules whose generated value is drawn once per call, which one call cannot give several entities. */
const DRAWN_ONCE = new Set<FieldRule["rule"]>(["unique", "renewed"]);

/** A bulk answer from the recorded one: one element per written entity, rendered as the first recorded element shows its entity. */
const bulkResponse = (
  response: WriteResponse,
  recorded: JsonValue | undefined,
  written: readonly { readonly fields: JsonObject; readonly id: string }[],
): Result<JsonValue | undefined, string> => {
  if (response.shape === "empty") return ok(undefined);
  const [template] = Array.isArray(recorded) ? recorded : [];
  if (template === undefined)
    return err("The recorded response shows no element to render.");
  const elements: JsonValue[] = [];
  for (const entity of written) {
    const element = writtenResponse(
      { ...response, pointer: "" },
      template,
      entity,
    );
    if (!element.ok) return element;
    elements.push(element.value ?? null);
  }
  return ok(elements);
};

/** The held entities a bulk call names, with the members each gets, or a refusal for an entity the state does not hold. */
const namedTargets = (
  serving: StateServing,
  request: WriteRequest,
): Result<
  { readonly entity: StateEntity; readonly body: JsonObject | undefined }[],
  AnalysisError
> => {
  const { tool, plan, args } = request;
  const { address } = plan;
  const type = plan.target ?? "";
  const name = environmentToolArguments(tool, true).body;
  const body = name === undefined ? undefined : (args[name] as JsonValue);
  if (body !== undefined && !isLoadableValue(body))
    return err(unloadable(tool, "The body"));
  const named =
    address === undefined || address.by === "action"
      ? undefined
      : namedEntities(address, body, serving.store.type(type)?.id_field ?? "");
  if (named === undefined)
    return err(
      refused(
        tool,
        `Tool ${tool.name} names the entities it writes by their ids in its body, as its recording did.`,
      ),
    );
  const segments = callSegments(tool, args);
  if (segments === undefined)
    return err(refused(tool, `Tool ${tool.name} needs every path argument.`));
  const collection = bulkCollectionOf(type, segments, (text) => ({
    text,
    supplied: false,
  }));
  const targets = [];
  for (const { id, body: members } of named) {
    const entity = namedEntity(serving.store, type, {
      segments: collection,
      id,
    });
    if (entity === undefined)
      return err(
        refused(
          tool,
          `The state holds no ${type} entity ${id}; the state is unchanged.`,
        ),
      );
    targets.push({ entity, body: members });
  }
  return ok(targets);
};

/** Apply one served bulk call to every entity its body names and answer it; a refused call leaves the state unchanged. */
export const answerBulk = (
  serving: StateServing,
  request: WriteRequest,
): Result<StateAnswer, AnalysisError> => {
  const { tool, plan, args } = request;
  const targets = namedTargets(serving, request);
  if (!targets.ok) return targets;
  const update = plan.effect === "update";
  if (
    update &&
    targets.value.length > 1 &&
    plan.rules.some((rule) => DRAWN_ONCE.has(rule.rule))
  )
    return err(
      refused(
        tool,
        `Tool ${tool.name} generates a value per call, so it writes one entity per call here.`,
      ),
    );
  const [first] = targets.value;
  const observed = observedEntity(serving, plan) ?? {};
  const values = generator(serving, request, {
    name: first!.entity.collection,
    collection: serving.store.inCollection(
      first!.entity.type,
      first!.entity.collection,
    ),
    observed,
  });
  const written: StateEntity[] = [];
  for (const { entity, body } of targets.value) {
    if (!update) {
      written.push(entity);
      continue;
    }
    const fields = updatedFields(
      plan,
      { before: entity.fields, observed },
      {
        path: tool.path_template,
        pathValues: pathValues(tool, args),
        body,
        id: entity.id,
      },
      values.generate,
    );
    if (!fields.ok) return err(refused(tool, fields.error));
    const field = unloadableMember(fields.value);
    if (field !== undefined) return err(unloadable(tool, `Field ${field}`));
    written.push(updatedEntity(entity, fields.value));
  }
  const answer = writeAnswer(
    serving,
    request,
    (recorded) => bulkResponse(plan.response!, recorded, written),
    {
      source: "state",
      view: update ? "update" : "delete",
      type: first!.entity.type,
      collection: first!.entity.collection,
      id: first!.entity.id,
      ids: written.map((entity) => entity.id),
    },
  );
  if (!answer.ok) return answer;
  if (update) {
    const updated = serving.store.updateAll(written);
    if (!updated.ok) return updated;
  } else serving.store.removeAll(written);
  serving.store.commitWrite(values.taken);
  return answer;
};
