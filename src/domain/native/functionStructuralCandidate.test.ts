import { expect, it } from "vitest";

import { FUNCTION_COMPARISON_EXAMPLE } from "../../contracts/functionComparisonExample.js";
import { createAnalysisProfile } from "../analysisProfile.js";
import { createEvidence } from "../evidence.js";
import { jsonValueSchema } from "../jsonValue.js";
import { functionDossierSchema } from "../hopperValues.js";
import { functionStructuralCandidate } from "./functionStructuralCandidate.js";

const provider = {
  id: "function-structural-candidate-test",
  name: "Function structural candidate test",
  version: "1",
} as const;
const profile = createAnalysisProfile(provider, { purpose: "test" });
const source = functionDossierSchema.parse(
  FUNCTION_COMPARISON_EXAMPLE.left.normalized_result,
);

const candidateFor = (name: string): string | null => {
  const dossier = functionDossierSchema.parse({
    ...source,
    callees: [
      {
        address: "0x1010",
        name,
        classification: null,
        body: source.procedure.body,
      },
    ],
    unresolved_calls: [],
  });
  const evidence = createEvidence(
    {
      path: "/fixture/function-structural-candidate",
      sha256: "a".repeat(64),
      format: "mach-o",
      architecture: "x86_64",
    },
    provider,
    {
      operation: "analyze_function",
      parameters: { procedure: "main" },
      result: jsonValueSchema.parse(dossier),
      confidence: "derived",
      authority: "shipped-artifact",
      analysisProfile: profile,
      relationshipCoverage: { status: "complete" },
    },
  );
  return functionStructuralCandidate(evidence, dossier);
};

it("excludes blank callee names from structural candidates", () => {
  expect(candidateFor("helper")).not.toBeNull();
  expect(candidateFor("")).toBeNull();
  expect(candidateFor("   ")).toBeNull();
  expect(candidateFor("\t")).toBeNull();
});
