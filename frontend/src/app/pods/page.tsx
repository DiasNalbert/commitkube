import { redirect } from "next/navigation";

// Moved under the Kubernetes module; kept so existing links and bookmarks work.
export default function Page() {
  redirect("/kubernetes/pods");
}
