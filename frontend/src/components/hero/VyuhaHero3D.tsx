import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { 
  ShieldCheck, 
  Sparkles, 
  Terminal, 
  ArrowRight, 
  Cpu, 
  Database, 
  Network,
  Activity,
  Layers
} from 'lucide-react';

interface VyuhaHero3DProps {
  onStartInvestigation: () => void;
  onLoadSample: () => void;
  isSampleLoading?: boolean;
}

interface NodeData {
  id: string;
  label: string;
  category: string;
  details: string;
  color: number;
  position: THREE.Vector3;
}

export const VyuhaHero3D: React.FC<VyuhaHero3DProps> = ({
  onStartInvestigation,
  onLoadSample,
  isSampleLoading = false,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [activeNode, setActiveNode] = useState<string>('THREAT INTELLIGENCE');
  const [activeNodeDesc, setActiveNodeDesc] = useState<string>('Synthesizes multi-vector forensic indicators into a 0-100 threat index');
  const [webglSupported, setWebglSupported] = useState<boolean>(true);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // Check WebGL availability
    const canvasTest = document.createElement('canvas');
    const gl = canvasTest.getContext('webgl') || canvasTest.getContext('experimental-webgl');
    if (!gl) {
      setWebglSupported(false);
      return;
    }

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 8, 38);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    container.appendChild(renderer.domElement);

    // Group for all rotating elements
    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // 1. Central Core: Holographic Vyuha Shield (Icosahedron + Outer Wireframe)
    const coreGeometry = new THREE.IcosahedronGeometry(3.6, 1);
    const coreMaterial = new THREE.MeshPhysicalMaterial({
      color: 0x00f0ff,
      emissive: 0x0284c7,
      emissiveIntensity: 0.8,
      metalness: 0.4,
      roughness: 0.1,
      wireframe: false,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
    mainGroup.add(coreMesh);

    // Outer Wireframe Shield
    const wireGeometry = new THREE.IcosahedronGeometry(4.8, 1);
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: 0x8b5cf6,
      wireframe: true,
      transparent: true,
      opacity: 0.45,
    });
    const wireMesh = new THREE.Mesh(wireGeometry, wireMaterial);
    mainGroup.add(wireMesh);

    // Orbital Rings
    const ringGeometry = new THREE.TorusGeometry(18, 0.08, 16, 100);
    const ringMaterial = new THREE.MeshBasicMaterial({ color: 0x0284c7, transparent: true, opacity: 0.25 });
    const ringMesh1 = new THREE.Mesh(ringGeometry, ringMaterial);
    ringMesh1.rotation.x = Math.PI / 2.8;
    mainGroup.add(ringMesh1);

    const ringGeometry2 = new THREE.TorusGeometry(14, 0.06, 16, 100);
    const ringMaterial2 = new THREE.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.2 });
    const ringMesh2 = new THREE.Mesh(ringGeometry2, ringMaterial2);
    ringMesh2.rotation.x = -Math.PI / 3.2;
    ringMesh2.rotation.y = Math.PI / 6;
    mainGroup.add(ringMesh2);

    // 2. Interconnected Nodes Configuration
    const nodesData: NodeData[] = [
      { id: 'EMAIL', label: 'EMAIL', category: 'INGESTION', details: 'RFC 5322 MIME extraction, boundary parser & hash computation', color: 0x00f0ff, position: new THREE.Vector3(-14, 4, 2) },
      { id: 'SENDER', label: 'SENDER', category: 'AUTH MATRIX', details: 'SPF, DKIM, DMARC alignment & display name spoof detection', color: 0x38bdf8, position: new THREE.Vector3(-10, 8, -4) },
      { id: 'IP', label: 'IP', category: 'GEO-INTELLIGENCE', details: 'Autonomous System Number (ASN), ISP & origin coordinates', color: 0x06b6d4, position: new THREE.Vector3(-4, -6, 8) },
      { id: 'MTA HOPS', label: 'MTA HOPS', category: 'RELAY TRACE', details: 'Chronological Received headers chain & hop delay metrics', color: 0x6366f1, position: new THREE.Vector3(4, -8, 4) },
      { id: 'DOMAIN', label: 'DOMAIN', category: 'REPUTATION', details: 'Shannon entropy, typosquatting brand alerts & abuse tier', color: 0x8b5cf6, position: new THREE.Vector3(11, -2, -6) },
      { id: 'URL', label: 'URL', category: 'HYPERLINKS', details: 'Anchor text discrepancy, shortening redirect & homograph test', color: 0xa855f7, position: new THREE.Vector3(14, 5, 2) },
      { id: 'THREAT INTEL', label: 'THREAT INTEL', category: 'AI SYNTHESIS', details: 'Multi-vector threat scoring, NLP urgency lures & confidence index', color: 0x00f0ff, position: new THREE.Vector3(0, 11, -2) },
    ];

    const nodeMeshes: THREE.Mesh[] = [];
    const nodeGroup = new THREE.Group();
    mainGroup.add(nodeGroup);

    nodesData.forEach((data) => {
      // Node Sphere
      const geom = new THREE.SphereGeometry(1.2, 24, 24);
      const mat = new THREE.MeshStandardMaterial({
        color: data.color,
        emissive: data.color,
        emissiveIntensity: 0.6,
        roughness: 0.2,
        metalness: 0.8,
      });
      const mesh = new THREE.Mesh(geom, mat);
      mesh.position.copy(data.position);
      mesh.userData = data;
      nodeMeshes.push(mesh);
      nodeGroup.add(mesh);

      // Node Halo Ring
      const haloGeom = new THREE.RingGeometry(1.6, 1.8, 32);
      const haloMat = new THREE.MeshBasicMaterial({
        color: data.color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.5,
      });
      const haloMesh = new THREE.Mesh(haloGeom, haloMat);
      haloMesh.position.copy(data.position);
      haloMesh.lookAt(camera.position);
      nodeGroup.add(haloMesh);

      // Connection to Core
      const points = [data.position, new THREE.Vector3(0, 0, 0)];
      const lineGeom = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({
        color: data.color,
        transparent: true,
        opacity: 0.35,
      });
      const line = new THREE.Line(lineGeom, lineMat);
      nodeGroup.add(line);
    });

    // Inter-node connection network lines
    for (let i = 0; i < nodesData.length; i++) {
      const nextIndex = (i + 1) % nodesData.length;
      const points = [nodesData[i].position, nodesData[nextIndex].position];
      const curve = new THREE.CatmullRomCurve3([
        nodesData[i].position,
        new THREE.Vector3().addVectors(nodesData[i].position, nodesData[nextIndex].position).multiplyScalar(0.5).add(new THREE.Vector3(0, 1.5, 0)),
        nodesData[nextIndex].position
      ]);
      const lineGeom = new THREE.BufferGeometry().setFromPoints(curve.getPoints(20));
      const lineMat = new THREE.LineBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0.3,
      });
      const line = new THREE.Line(lineGeom, lineMat);
      nodeGroup.add(line);
    }

    // 3. Cyber Dust / Particle Cloud
    const particleCount = 200;
    const particleGeom = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 50;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 40;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 40;

      // Cyan to purple mix
      if (Math.random() > 0.5) {
        colors[i * 3] = 0.0;
        colors[i * 3 + 1] = 0.94;
        colors[i * 3 + 2] = 1.0;
      } else {
        colors[i * 3] = 0.54;
        colors[i * 3 + 1] = 0.36;
        colors[i * 3 + 2] = 0.96;
      }
    }

    particleGeom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    particleGeom.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    const particleMat = new THREE.PointsMaterial({
      size: 0.35,
      vertexColors: true,
      transparent: true,
      opacity: 0.65,
    });
    const particles = new THREE.Points(particleGeom, particleMat);
    scene.add(particles);

    // 4. Lighting
    const ambientLight = new THREE.AmbientLight(0x0a1026, 2.5);
    scene.add(ambientLight);

    const coreLight = new THREE.PointLight(0x00f0ff, 4, 40);
    coreLight.position.set(0, 0, 0);
    scene.add(coreLight);

    const violetLight = new THREE.PointLight(0x8b5cf6, 3, 50);
    violetLight.position.set(15, 10, 15);
    scene.add(violetLight);

    // 5. Mouse Interaction & Raycasting
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(-100, -100);
    let targetRotationX = 0;
    let targetRotationY = 0;

    const handleMouseMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      targetRotationY = mouse.x * 0.4;
      targetRotationX = mouse.y * 0.2;
    };

    container.addEventListener('mousemove', handleMouseMove);

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth;
      const newHeight = container.clientHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    // 6. Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Gentle continuous rotation
      coreMesh.rotation.y = elapsedTime * 0.3;
      coreMesh.rotation.x = Math.sin(elapsedTime * 0.5) * 0.2;
      wireMesh.rotation.y = -elapsedTime * 0.2;
      wireMesh.rotation.z = Math.cos(elapsedTime * 0.3) * 0.15;

      ringMesh1.rotation.z = elapsedTime * 0.1;
      ringMesh2.rotation.z = -elapsedTime * 0.08;

      // Smooth mouse-follow interpolation
      mainGroup.rotation.y += (targetRotationY - mainGroup.rotation.y) * 0.05;
      mainGroup.rotation.x += (-targetRotationX - mainGroup.rotation.x) * 0.05;

      // Pulse particle drift
      particles.rotation.y = elapsedTime * 0.03;

      // Raycasting for hovered node
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        const intersectedMesh = intersects[0].object as THREE.Mesh;
        const data = intersectedMesh.userData as NodeData;
        if (data && data.label) {
          setActiveNode(data.label);
          setActiveNodeDesc(data.details);
          container.style.cursor = 'pointer';
        }
      } else {
        container.style.cursor = 'default';
      }

      renderer.render(scene, camera);
    };

    animate();

    // Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      container.removeEventListener('mousemove', handleMouseMove);

      coreGeometry.dispose();
      coreMaterial.dispose();
      wireGeometry.dispose();
      wireMaterial.dispose();
      ringGeometry.dispose();
      ringMaterial.dispose();
      ringGeometry2.dispose();
      ringMaterial2.dispose();
      particleGeom.dispose();
      particleMat.dispose();

      if (renderer.domElement && renderer.domElement.parentNode) {
        renderer.domElement.parentNode.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, []);

  return (
    <div className="relative w-full rounded-3xl overflow-hidden glass-panel border border-cyan-500/20 shadow-2xl p-6 sm:p-10 my-4">
      {/* Background Cyber Ambient Lights */}
      <div className="absolute -top-32 -left-32 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-32 -right-32 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center relative z-10">
        {/* Left Column: Mission Narrative & Launch Actions */}
        <div className="lg:col-span-6 space-y-6">
          {/* Badge */}
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyan-950/70 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400"></span>
            </span>
            <span className="font-semibold tracking-wide">NEXT-GEN DIGITAL FORENSICS ENGINE</span>
          </div>

          {/* Heading */}
          <div className="space-y-3">
            <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight font-display text-white">
              AI-Powered Digital <br />
              <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
                Threat Intelligence
              </span>
            </h1>
            <p className="text-sm sm:text-base text-slate-300 font-sans leading-relaxed max-w-xl">
              Investigate suspicious emails. Trace digital evidence. Understand threats before they become incidents.
            </p>
          </div>

          {/* Value Props Pills */}
          <div className="flex flex-wrap gap-2 text-xs font-mono">
            <span className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-700/80 text-slate-300 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              Cryptographic Integrity (SHA-256)
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-700/80 text-slate-300 flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-sky-400" />
              MTA Hop Trajectory
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-700/80 text-slate-300 flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              Explainable AI Reasoner
            </span>
          </div>

          {/* Interactive CTAs */}
          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              onClick={onStartInvestigation}
              className="flex items-center space-x-2.5 px-6 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl shadow-lg shadow-cyan-500/25 transition-all duration-300 hover:scale-[1.02] text-sm"
            >
              <Terminal className="w-4 h-4 text-slate-950" />
              <span>Launch Investigation Workstation</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>

            <button
              onClick={onLoadSample}
              disabled={isSampleLoading}
              className="flex items-center space-x-2 px-5 py-3.5 rounded-xl text-sm font-semibold bg-slate-900/90 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-cyan-500/50 shadow-md transition disabled:opacity-60"
            >
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span>{isSampleLoading ? 'Simulating Analysis...' : 'Evaluate Live Phishing Sample'}</span>
            </button>
          </div>

          {/* Active Node Telemetry Card */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-cyan-500/20 flex items-start space-x-3 text-xs max-w-lg">
            <Activity className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-cyan-300 uppercase">{activeNode}</span>
                <span className="text-[10px] text-slate-500 font-mono">NODE ACTIVE TELEMETRY</span>
              </div>
              <p className="text-slate-300 mt-0.5 text-[11px] leading-tight">{activeNodeDesc}</p>
            </div>
          </div>
        </div>

        {/* Right Column: 3D Visualization Canvas Container */}
        <div className="lg:col-span-6 relative flex items-center justify-center">
          <div
            ref={mountRef}
            className="w-full h-[360px] sm:h-[420px] rounded-2xl relative overflow-hidden bg-gradient-to-b from-slate-950/40 to-slate-900/20"
          >
            {/* Fallback for non-WebGL devices */}
            {!webglSupported && (
              <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center space-y-3">
                <Layers className="w-12 h-12 text-cyan-400 animate-pulse" />
                <h4 className="text-sm font-bold text-white font-mono">VYUHA AI DEFENSE CORE</h4>
                <p className="text-xs text-slate-400 max-w-xs">
                  EMAIL → SENDER → IP → MTA HOPS → DOMAIN → URL → THREAT SCORE
                </p>
              </div>
            )}

            {/* In-Canvas High-Tech HUD Overlays */}
            <div className="absolute top-3 left-3 px-2.5 py-1 rounded-md bg-slate-950/80 border border-slate-800 text-[10px] font-mono text-cyan-400 pointer-events-none flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span>CORE 3D INTERCONNECT // 7 ACTIVE VECTORS</span>
            </div>

            <div className="absolute bottom-3 right-3 px-2.5 py-1 rounded-md bg-slate-950/80 border border-slate-800 text-[10px] font-mono text-slate-400 pointer-events-none">
              ORBIT CAMERA // DRAG / HOVER NODES
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VyuhaHero3D;
