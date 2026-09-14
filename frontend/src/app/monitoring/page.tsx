import { redirect } from "next/navigation";

// Availability was backed by ArgoCD polling. ArgoCD is now used only to deploy
// applications, and uptime/change history come from the Kubernetes API instead.
export default function Page() {
  redirect("/kubernetes/workloads");
}
