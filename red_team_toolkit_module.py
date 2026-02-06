// ./RedTeamToolkit.tsx
import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Bug, Eye, KeyRound, Terminal, Ghost, UploadCloud } from "lucide-react";
import { injectGhostShell } from "./GhostShellEngine";
import { ReconModule, ExploitModule } from "./redteam-core";

interface RedTeamToolkitProps {
  stealthLoad?: boolean;
  onTrigger?: () => void;
  ttlSeconds?: number;
  hashTrigger?: string;
  websocketCommand?: string;
}

function FragmentUploader() {
  const [status, setStatus] = useState("Drop .txt with base64 fragments");

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;

    const text = await file.text();
    const lines = text.trim().split("\n");

    lines.forEach((line, i) => {
      const cleaned = line.replace(/[^A-Za-z0-9+/=]/g, '');
      // @ts-ignore
      window.injectGhostFragment(i, cleaned);
    });

    localStorage.setItem("ghost_fragments", text);
    setStatus(`Injected ${lines.length} fragments.`);
  };

  useEffect(() => {
    const saved = localStorage.getItem("ghost_fragments");
    if (saved) {
      const lines = saved.trim().split("\n");
      lines.forEach((line, i) => {
        const cleaned = line.replace(/[^A-Za-z0-9+/=]/g, '');
        // @ts-ignore
        window.injectGhostFragment(i, cleaned);
      });
      setStatus(`Restored ${lines.length} fragments.`);
    }
  }, []);

  return (
    <div
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
      className="border border-dashed rounded-md p-4 mt-4 bg-muted text-center text-sm"
    >
      <UploadCloud className="mx-auto mb-2" />
      {status}
    </div>
  );
}

export default function RedTeamToolkit({ stealthLoad, onTrigger, ttlSeconds = 0, hashTrigger, websocketCommand }: RedTeamToolkitProps) {
  const [ghostLoaded, setGhostLoaded] = useState(false);
  const [reconOutput, setReconOutput] = useState("");
  const [target, setTarget] = useState("");

  // TTL UNLOADING
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (ghostLoaded && ttlSeconds > 0) {
      timer = setTimeout(() => setGhostLoaded(false), ttlSeconds * 1000);
    }
    return () => clearTimeout(timer);
  }, [ghostLoaded, ttlSeconds]);

  // HASH TRIGGER
  useEffect(() => {
    if (hashTrigger && window.location.hash === hashTrigger) {
      injectGhostShell();
      setGhostLoaded(true);
      onTrigger?.();
    }
  }, [hashTrigger]);

  // WS TRIGGER
  useEffect(() => {
    if (!websocketCommand) return;
    const socket = new WebSocket("ws://localhost:8080");
    socket.onmessage = (event) => {
      if (event.data === websocketCommand) {
        injectGhostShell();
        setGhostLoaded(true);
        onTrigger?.();
      }
    };
    return () => socket.close();
  }, [websocketCommand]);

  if (stealthLoad && !ghostLoaded) return null;

  const loadGhostShell = () => {
    injectGhostShell();
    setGhostLoaded(true);
    onTrigger?.();
  };

  const runRecon = async () => {
    const result = await ReconModule.runNmapScan(target);
    setReconOutput(result as string);
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
      <Card className="rounded-2xl shadow-xl">
        <CardContent className="p-4">
          <Tabs defaultValue="recon">
            <TabsList className="flex w-full justify-around">
              <TabsTrigger value="recon"><Eye className="mr-2" /> Recon</TabsTrigger>
              <TabsTrigger value="exploit"><Bug className="mr-2" /> Exploit</TabsTrigger>
              <TabsTrigger value="payload"><KeyRound className="mr-2" /> Payloads</TabsTrigger>
              <TabsTrigger value="console"><Terminal className="mr-2" /> Console</TabsTrigger>
              <TabsTrigger value="ghost"><Ghost className="mr-2" /> GhostShell</TabsTrigger>
            </TabsList>

            <TabsContent value="recon">
              <p className="text-sm mb-2">Quick recon tools:</p>
              <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target IP" className="border p-1 rounded w-full mb-2" />
              <Button variant="secondary" className="w-full mb-2" onClick={runRecon}>Run Nmap Scan</Button>
              <pre className="text-xs bg-black text-green-400 p-2 rounded whitespace-pre-wrap">{reconOutput}</pre>
            </TabsContent>

            <TabsContent value="exploit">
              <p className="text-sm">Exploit modules (stubbed).</p>
              <Button className="w-full mt-2" variant="destructive" onClick={() => alert('SMB exploit trigger stub')}>Exploit SMBv1</Button>
            </TabsContent>

            <TabsContent value="payload">
              <p className="text-sm">Payload generators (coming soon).</p>
            </TabsContent>

            <TabsContent value="console">
              <p className="text-sm">Command interface (stubbed).</p>
            </TabsContent>

            <TabsContent value="ghost">
              <p className="text-sm">Inject volatile GhostShell into memory.</p>
              <Button onClick={loadGhostShell} variant="ghost" className="mt-2 w-full">
                {ghostLoaded ? "GhostShell Loaded" : "Load GhostShell"}
              </Button>
              {ghostLoaded && <FragmentUploader />}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}