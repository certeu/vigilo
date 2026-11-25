import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../../api/client";
import { greyboxApi } from "./api";
import { startErrorMessage } from "./NewGreyboxForm";

/**
 * Start a run (POST /greybox/targets/{id}/runs) and open its workspace.
 *
 * The caller owns the idempotency key: keep the same key for retries of one user
 * intent (a double click or a retry after a network error returns the same run with
 * 200), and make a new one for a new intent.
 *
 * A 409 with `run_id` opens the already active run instead of failing. Any other
 * error is thrown with a user-facing message (so ConfirmDialog can show it).
 */
export function useStartRun() {
  const navigate = useNavigate();
  return useCallback(
    async (targetId: string, idempotencyKey: string) => {
      try {
        const run = await greyboxApi.startRun(targetId, {
          authorization_confirmed: true,
          idempotency_key: idempotencyKey,
        });
        navigate(`/greybox/runs/${run.id}`, { state: { notice: "Analysis started." } });
      } catch (e) {
        if (e instanceof ApiError && e.status === 409) {
          const runId = (e.body as { run_id?: string } | null)?.run_id;
          if (runId) {
            navigate(`/greybox/runs/${runId}`, {
              state: { notice: "A run for this target was already active, so it is shown instead of starting a new one." },
            });
            return;
          }
        }
        throw new Error(`The analysis did not start: ${startErrorMessage(e)}`);
      }
    },
    [navigate],
  );
}
