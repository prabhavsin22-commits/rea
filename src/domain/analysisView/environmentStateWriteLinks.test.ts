import { describe, expect, it } from "vitest";

import type { JsonValue } from "../jsonValue.js";
import type { StateRecordFacts } from "./environmentStateRules.js";
import { creationLimit } from "./environmentStateWriteLinks.js";

const record = (
  ordinal: number,
  method: string,
  path: string,
  [start, end] = [ordinal, ordinal],
): StateRecordFacts => ({
  ordinal,
  method,
  path,
  query: undefined,
  status: 200,
  start,
  end,
});

/** The creation limit of `/api/projects` over list reads and a POST returning `created`, in ordinal order. */
const projectsLimit = (
  reads: readonly StateRecordFacts[],
  post: StateRecordFacts,
  bodies: ReadonlyMap<number, JsonValue>,
  created: readonly string[],
) =>
  creationLimit(
    [{ record: post, ids: created }],
    {
      type: "/api/projects",
      tools: [
        {
          name: "get_projects",
          method: "GET",
          path_template: "/api/projects",
          record_ordinals: reads.map((read) => read.ordinal),
        },
      ],
      records: new Map([...reads, post].map((at) => [at.ordinal, at])),
      position: (at) => at.ordinal,
      body: (ordinal) => bodies.get(ordinal),
    },
    undefined,
  );

describe("creation limits", () => {
  it("reads the ids of a list body longer than a call's arguments can spread", () => {
    // A million elements overflow the argument limit of a spread, here and in the test workers' larger stack.
    const [list, post, later] = [
      record(0, "GET", "/api/metrics"),
      record(1, "POST", "/api/imports"),
      record(2, "GET", "/api/metrics"),
    ];
    const bodies = new Map<number, JsonValue>([
      [0, Array.from({ length: 1_000_000 }, () => 0)],
      [2, [{ id: "1003" }]],
    ]);
    const limit = creationLimit(
      [{ record: post, ids: ["1003"] }],
      {
        type: "/api/metrics",
        tools: [
          {
            name: "get_metrics",
            method: "GET",
            path_template: "/api/metrics",
            record_ordinals: [0, 2],
          },
        ],
        records: new Map([list, post, later].map((at) => [at.ordinal, at])),
        position: (at) => at.ordinal,
        body: (ordinal) => bodies.get(ordinal),
      },
      undefined,
    );
    expect(limit).toBe(post);
  });

  it("counts a read still running when the POST began as showing what it made", () => {
    const earlier = record(0, "GET", "/api/projects", [0, 5]);
    const post = record(2, "POST", "/api/imports", [20, 25]);
    const bodies = new Map<number, JsonValue>([
      [0, [{ id: "proj-0001" }]],
      [1, [{ id: "proj-0001" }, { id: "proj-0002" }]],
    ]);
    // The second list began before the POST but ended after it began, so it may show the import.
    const overlapping = record(1, "GET", "/api/projects", [10, 40]);
    expect(
      projectsLimit([earlier, overlapping], post, bodies, ["proj-0002"]),
    ).toBe(post);
    const finished = record(1, "GET", "/api/projects", [10, 15]);
    expect(
      projectsLimit([earlier, finished], post, bodies, ["proj-0002"]),
    ).toBeUndefined();
  });

  it("reads a list's ids from a suffix-named field when no identity name identifies its entities", () => {
    const [list, post, later] = [
      record(0, "GET", "/api/projects"),
      record(1, "POST", "/api/imports"),
      record(2, "GET", "/api/projects"),
    ];
    const bodies = new Map<number, JsonValue>([
      [0, [{ projectId: "proj-0001", name: "Alpha" }]],
      [
        2,
        [
          { projectId: "proj-0001", name: "Alpha" },
          { projectId: "proj-0002", name: "Beta" },
        ],
      ],
    ]);
    expect(projectsLimit([list, later], post, bodies, ["proj-0002"])).toBe(
      post,
    );
  });

  it("reads no suffix-named field as a list's ids when an id field already identifies its entities", () => {
    const [list, post, later] = [
      record(0, "GET", "/api/projects"),
      record(1, "POST", "/api/users/user-0003/activate"),
      record(2, "GET", "/api/projects"),
    ];
    const project = (id: string, ownerId: string) => ({ id, ownerId });
    const bodies = new Map<number, JsonValue>([
      [
        0,
        [project("proj-0001", "user-0001"), project("proj-0002", "user-0002")],
      ],
      [
        2,
        [project("proj-0001", "user-0003"), project("proj-0002", "user-0002")],
      ],
    ]);
    // The owner the user call returned is no project the call made.
    expect(
      projectsLimit([list, later], post, bodies, ["user-0003"]),
    ).toBeUndefined();
  });

  it("reads the ids a list shows from its listed entities, not the entities they nest", () => {
    const [list, post, later] = [
      record(0, "GET", "/api/projects"),
      record(1, "POST", "/api/users"),
      record(2, "GET", "/api/projects"),
    ];
    const project = (owner: string) => ({
      id: "proj-0001",
      owner: { id: owner },
    });
    const bodies = new Map<number, JsonValue>([
      [0, [project("user-0001")]],
      [2, { projects: [project("user-0009")] }],
    ]);
    expect(
      projectsLimit([list, later], post, bodies, ["user-0009"]),
    ).toBeUndefined();
  });
});
