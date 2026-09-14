"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="persistentvolumeclaims"
      title="Persistent Volume Claims"
      subtitle="Storage claims, their bound volumes and capacity"
      namespaced={true}
      columns={[
        { id: "name", label: "Claim", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "status", label: "Status" },
        { id: "capacity", label: "Capacity", align: "right" },
        { id: "storageClass", label: "Storage class" },
        { id: "accessModes", label: "Access modes" },
        { id: "volume", label: "Volume", mono: true, truncate: true },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
