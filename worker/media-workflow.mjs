/**
 * The Workflow that drives one media job (an image batch or a video webhook watch).
 * Bind it as MEDIA_JOBS (docs/media-storage.md); without the binding the Container
 * refuses batches with `batches_not_configured`. The job logic lives in media-jobs.mjs.
 */
import { WorkflowEntrypoint } from "cloudflare:workers";
import { getContainer } from "@cloudflare/containers";
import { runMediaJob } from "./media-jobs.mjs";

export class MediaJobWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    const container = getContainer(this.env.MULTILLM_PROXY_CONTAINER, "primary");
    await runMediaJob(this.env, event.payload?.id, step, { container: request => container.fetch(request) });
  }
}
