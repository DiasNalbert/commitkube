"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="replicasets"
      title="ReplicaSets"
      subtitle="Current and superseded revisions; a ReplicaSet scaled to zero is a retired revision, not a fault"
      namespaced={true}
      columns={[
        { id: "name", label: "ReplicaSet", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "owner", label: "Owned by", mono: true, truncate: true },
        { id: "desired", label: "Desired", align: "right" },
        { id: "current", label: "Current", align: "right" },
        { id: "ready", label: "Ready", align: "right" },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
