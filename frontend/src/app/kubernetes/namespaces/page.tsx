"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="namespaces"
      title="Namespaces"
      subtitle="All namespaces in the cluster, with how many pods each one holds"
      namespaced={false}
      columns={[
        { id: "name", label: "Name", mono: true },
        { id: "status", label: "Phase" },
        { id: "pods", label: "Pods", align: "right" },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
