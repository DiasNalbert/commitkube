"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="statefulsets"
      title="StatefulSets"
      subtitle="Ordered, persistent workloads and their governing service"
      namespaced={true}
      columns={[
        { id: "name", label: "StatefulSet", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "ready", label: "Ready", align: "right" },
        { id: "service", label: "Service", mono: true, truncate: true },
        { id: "image", label: "Image", mono: true, truncate: true },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
