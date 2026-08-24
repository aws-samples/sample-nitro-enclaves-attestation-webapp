import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Paper,
  IconButton,
  Dialog,
  DialogContent,
  DialogTitle,
  Slider,
  Tooltip,
  Divider,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Fullscreen as FullscreenIcon,
  Close as CloseIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  CenterFocusWeak as CenterIcon,
  FitScreen as FitScreenIcon,
} from '@mui/icons-material';
import mermaid from 'mermaid';

// Initialize mermaid with dark theme
mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  themeVariables: {
    primaryColor: '#132f4c',
    primaryTextColor: '#fff',
    primaryBorderColor: '#90caf9',
    lineColor: '#90caf9',
    secondaryColor: '#0a1929',
    tertiaryColor: '#1e3a5f',
  },
});

const architectureDiagram = `
flowchart TB
    subgraph Client["🌐 Client Browser"]
        UI[React Frontend]
        Verify[Attestation Verifier<br/>COSE/CBOR]
        HPKE_Client[HPKE Encryption<br/>RFC 9180]
    end

    subgraph AWS["☁️ AWS Cloud"]
        subgraph Amplify["AWS Amplify"]
            HostedUI[Hosted UI]
            Cognito[Amazon Cognito]
        end

        subgraph APILayer["API Layer"]
            APIGW[API Gateway]
            VPCLink[VPC Link]
            NLB[Network Load Balancer]
        end

        subgraph VPC["VPC - Private Isolated Subnet"]
            subgraph Host["🖥️ Nitro Host (Physical Server)"]
                subgraph EC2["EC2 Parent Instance"]
                    Parent[Parent VM]
                    Proxy[Enclave inbound proxy<br/>TCP :8000 to vsock]
                end

                subgraph Enclave["🔒 Nitro Enclave (Isolated VM)"]
                    NSM[NSM Device]
                    HPKE_Enclave[HPKE API<br/>P-256 + AES-128-GCM]
                    PrivateKey[Private Key 🔑<br/>Never Leaves Enclave]
                end
            end
        end

        subgraph CICD["CI/CD Pipeline"]
            S3[S3 Bucket - Source & Artifacts]
            EventBridge[EventBridge Trigger]
            CodePipeline[CodePipeline]
            CodeBuild[CodeBuild - EIF Builder]
            CodeDeploy[CodeDeploy]
        end

        subgraph Storage["Storage & Config"]
            SSM[SSM Parameter Store]
            VPCEndpoints[VPC Endpoints<br/>S3, SSM, STS, CloudWatch]
        end
    end

    UI --> |1. Auth| Cognito
    Cognito --> |JWT Token| UI
    UI --> |2. Request Attestation| APIGW
    APIGW --> VPCLink --> NLB --> Proxy
    Proxy --> |vsock CID 16| HPKE_Enclave
    HPKE_Enclave --> |Get Attestation| NSM
    NSM --> |Attestation Doc + HPKE Public Key| HPKE_Enclave
    HPKE_Enclave --> Proxy --> APIGW --> UI

    UI --> |3. Verify in Browser| Verify
    Verify --> |4. Extract HPKE Public Key| HPKE_Client
    HPKE_Client --> |5. HPKE Encrypted Request| APIGW
    APIGW --> Proxy --> HPKE_Enclave
    HPKE_Enclave --> |Decrypt| PrivateKey
    PrivateKey --> |6. HPKE Encrypted Response| HPKE_Enclave
    HPKE_Enclave --> Proxy --> APIGW --> HPKE_Client
    HPKE_Client --> |7. Decrypt Response| UI

    S3 --> |Object Created| EventBridge
    EventBridge --> CodePipeline
    CodePipeline --> CodeBuild
    CodeBuild --> |Build EIF| S3
    CodePipeline --> CodeDeploy
    CodeDeploy --> EC2
    SSM --> |Config| Parent
    S3 --> |Download EIF| Parent
    Parent --> |Launch| Enclave
    EC2 -.-> VPCEndpoints

    classDef enclave fill:#1a472a,stroke:#66bb6a,stroke-width:2px
    classDef aws fill:#232f3e,stroke:#ff9900,stroke-width:1px
    classDef client fill:#1e3a5f,stroke:#90caf9,stroke-width:1px
    classDef hpke fill:#4a148c,stroke:#ce93d8,stroke-width:2px
    classDef cicd fill:#1b2838,stroke:#d29922,stroke-width:1px

    class Enclave enclave
    class AWS,Amplify,APILayer,VPC,Storage,Host aws
    class Client client
    class EC2 aws
    class HPKE_Client,HPKE_Enclave hpke
    class CICD cicd
`;

const flowDiagram = `
sequenceDiagram
    participant B as Browser
    participant C as Cognito
    participant A as API Gateway
    participant E as Enclave
    participant NSM as NSM Device

    Note over B,NSM: Authentication
    B->>C: 1. Authenticate
    C-->>B: JWT Token

    Note over B,NSM: Attestation and Key Exchange
    B->>A: 2. POST /api/attestation
    A->>A: Validate JWT
    A->>E: Forward via vsock
    E->>E: Generate HPKE Key Pair P-256
    E->>NSM: get_attestation_document
    NSM-->>E: COSE_Sign1 signed document
    E-->>A: Attestation bytes
    A-->>B: Base64 CBOR attestation

    Note over B: Browser-Side Verification
    B->>B: 3. Decode Base64 to CBOR
    B->>B: 4. Parse COSE_Sign1
    B->>B: 5. Verify cert chain to AWS Root CA
    B->>B: 6. Verify COSE signature P-384
    B->>B: 7. Validate nonce
    B->>B: 8. Extract P-256 public key

    Note over B,NSM: HPKE Encrypted Communication
    B->>B: 9. Generate ephemeral keypair
    B->>B: 10. Derive shared secret via ECDH
    B->>B: 11. AES-GCM encrypt message
    B->>A: 12. POST /api/decrypt/hpke
    A->>E: Forward encrypted payload
    E->>E: ECDH derive shared secret
    E->>E: AES-GCM decrypt
    E->>E: Encrypt response
    E-->>A: encrypted_response + iv
    A-->>B: Forward encrypted response
    B->>B: 13. Decrypt with response key
`;

const cicdDiagram = `
flowchart LR
    subgraph Dev["👨‍💻 Developer"]
        Code["Source Code"]
        Script["package-and-upload.sh"]
    end

    subgraph Pipeline["🔄 CI/CD"]
        S3["📦 S3<br/>source.zip"]
        EB["⚡ EventBridge"]
        CP["CodePipeline"]
        CB["🔨 CodeBuild<br/>Docker + nitro-cli"]
        CD["🚀 CodeDeploy"]
    end

    subgraph Target["💻 EC2"]
        Stop["Stop services"]
        DL["Download EIF"]
        Launch["Launch enclave"]
        Start["Start services"]
        Stop --> DL --> Launch --> Start
    end

    Code --> Script --> S3
    S3 --> EB --> CP
    CP --> CB --> CD --> Stop
`;

// Interactive diagram viewer component
function DiagramViewer({ svgContent, title }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [viewportRect, setViewportRect] = useState({ x: 0, y: 0, width: 100, height: 100 });

  const mainViewerRef = useRef(null);
  const miniMapRef = useRef(null);
  const containerRef = useRef(null);

  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const handleZoomIn = () => setZoom(prev => Math.min(prev + 0.25, 4));
  const handleZoomOut = () => setZoom(prev => Math.max(prev - 0.25, 0.5));
  const handleReset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };
  const handleFit = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Update viewport rectangle for mini-map
  useEffect(() => {
    if (containerRef.current && zoom > 0) {
      const container = containerRef.current;
      const containerWidth = container.clientWidth;
      const containerHeight = container.clientHeight;

      const visibleWidth = (100 / zoom);
      const visibleHeight = (100 / zoom);
      const visibleX = Math.max(0, Math.min(100 - visibleWidth, (-pan.x / (containerWidth * zoom)) * 100 + 50 - visibleWidth/2));
      const visibleY = Math.max(0, Math.min(100 - visibleHeight, (-pan.y / (containerHeight * zoom)) * 100 + 50 - visibleHeight/2));

      setViewportRect({
        x: visibleX,
        y: visibleY,
        width: visibleWidth,
        height: visibleHeight,
      });
    }
  }, [zoom, pan]);

  // Mouse handlers for panning
  const handleMouseDown = (e) => {
    if (zoom > 1) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = useCallback((e) => {
    if (isDragging && containerRef.current) {
      const container = containerRef.current;
      const maxPanX = (container.clientWidth * (zoom - 1)) / 2;
      const maxPanY = (container.clientHeight * (zoom - 1)) / 2;

      const newX = Math.max(-maxPanX, Math.min(maxPanX, e.clientX - dragStart.x));
      const newY = Math.max(-maxPanY, Math.min(maxPanY, e.clientY - dragStart.y));

      setPan({ x: newX, y: newY });
    }
  }, [isDragging, dragStart, zoom]);

  const handleMouseUp = () => setIsDragging(false);

  // Handle mini-map click to pan
  const handleMiniMapClick = (e) => {
    if (!miniMapRef.current || !containerRef.current) return;

    const rect = miniMapRef.current.getBoundingClientRect();
    const clickX = ((e.clientX - rect.left) / rect.width) * 100;
    const clickY = ((e.clientY - rect.top) / rect.height) * 100;

    const container = containerRef.current;
    const maxPanX = (container.clientWidth * (zoom - 1)) / 2;
    const maxPanY = (container.clientHeight * (zoom - 1)) / 2;

    const newPanX = ((50 - clickX) / 50) * maxPanX;
    const newPanY = ((50 - clickY) / 50) * maxPanY;

    setPan({
      x: Math.max(-maxPanX, Math.min(maxPanX, newPanX)),
      y: Math.max(-maxPanY, Math.min(maxPanY, newPanY)),
    });
  };

  // Handle wheel zoom
  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom(prev => Math.max(0.5, Math.min(4, prev + delta)));
  };

  // Escape to close
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && open) handleClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open]);

  return (
    <>
      {/* Thumbnail with fullscreen button */}
      <Box sx={{ position: 'relative' }}>
        <Paper
          sx={{
            p: 2,
            bgcolor: 'background.default',
            overflow: 'auto',
            '& svg': { maxWidth: '100%', height: 'auto' },
            cursor: 'pointer',
          }}
          onClick={handleOpen}
          // nosemgrep: react-dangerouslysetinnerhtml -- svgContent is mermaid-rendered SVG from a static, in-repo diagram definition (no user input); mermaid v10 sanitizes its own output.
          dangerouslySetInnerHTML={{ __html: svgContent }}
        />
        <Tooltip title={t('diagram.tooltips.openFullscreen')}>
          <IconButton
            sx={{
              position: 'absolute',
              top: 8,
              right: 8,
              bgcolor: 'primary.main',
              color: 'white',
              '&:hover': { bgcolor: 'primary.dark' },
            }}
            onClick={handleOpen}
          >
            <FullscreenIcon />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Fullscreen dialog with zoom/pan controls and navigator */}
      <Dialog
        open={open}
        onClose={handleClose}
        maxWidth={false}
        fullWidth
        PaperProps={{
          sx: {
            width: '96vw',
            height: '94vh',
            maxWidth: '96vw',
            maxHeight: '94vh',
            bgcolor: 'background.paper',
          }
        }}
      >
        <DialogTitle sx={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          py: 1,
          borderBottom: 1,
          borderColor: 'divider',
        }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Tooltip title={t('diagram.tooltips.zoomOut')}>
              <IconButton onClick={handleZoomOut} size="small">
                <ZoomOutIcon />
              </IconButton>
            </Tooltip>
            <Typography variant="body2" sx={{ minWidth: 50, textAlign: 'center' }}>
              {Math.round(zoom * 100)}%
            </Typography>
            <Tooltip title={t('diagram.tooltips.zoomIn')}>
              <IconButton onClick={handleZoomIn} size="small">
                <ZoomInIcon />
              </IconButton>
            </Tooltip>
            <Divider orientation="vertical" flexItem sx={{ mx: 1 }} />
            <Tooltip title={t('diagram.tooltips.reset')}>
              <IconButton onClick={handleReset} size="small">
                <CenterIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('diagram.tooltips.fit')}>
              <IconButton onClick={handleFit} size="small">
                <FitScreenIcon />
              </IconButton>
            </Tooltip>
            <Divider orientation="vertical" flexItem sx={{ mx: 1 }} />
            <Tooltip title={t('diagram.tooltips.close')}>
              <IconButton onClick={handleClose} size="small">
                <CloseIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ p: 0, display: 'flex', overflow: 'hidden' }}>
          {/* Main viewer area */}
          <Box
            ref={containerRef}
            sx={{
              flex: 1,
              overflow: 'hidden',
              position: 'relative',
              cursor: zoom > 1 ? (isDragging ? 'grabbing' : 'grab') : 'default',
              bgcolor: '#0a1929',
            }}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
          >
            <Box
              ref={mainViewerRef}
              sx={{
                position: 'absolute',
                top: '50%',
                left: '50%',
                transform: `translate(-50%, -50%) translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                transformOrigin: 'center center',
                transition: isDragging ? 'none' : 'transform 0.1s ease-out',
                '& svg': {
                  maxWidth: 'none',
                  height: 'auto',
                  display: 'block',
                },
              }}
              // nosemgrep: react-dangerouslysetinnerhtml -- svgContent is mermaid-rendered SVG from a static, in-repo diagram definition (no user input); mermaid v10 sanitizes its own output.
              dangerouslySetInnerHTML={{ __html: svgContent }}
            />
          </Box>

          {/* Mini-map / Navigator */}
          <Box
            sx={{
              width: 200,
              borderLeft: 1,
              borderColor: 'divider',
              bgcolor: 'background.default',
              p: 1,
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <Typography variant="caption" color="text.secondary" sx={{ mb: 1 }}>
              {t('diagram.view.navigator')}
            </Typography>

            {/* Mini-map thumbnail */}
            <Box
              ref={miniMapRef}
              sx={{
                position: 'relative',
                width: '100%',
                height: 150,
                bgcolor: '#0a1929',
                borderRadius: 1,
                overflow: 'hidden',
                cursor: 'crosshair',
                '& svg': {
                  width: '100%',
                  height: '100%',
                  objectFit: 'contain',
                },
              }}
              onClick={handleMiniMapClick}
            >
              <Box
                sx={{
                  width: '100%',
                  height: '100%',
                  opacity: 0.7,
                  '& svg': { width: '100%', height: '100%' },
                }}
                // nosemgrep: react-dangerouslysetinnerhtml -- svgContent is mermaid-rendered SVG from a static, in-repo diagram definition (no user input); mermaid v10 sanitizes its own output.
                dangerouslySetInnerHTML={{ __html: svgContent }}
              />
              {/* Viewport indicator */}
              <Box
                sx={{
                  position: 'absolute',
                  left: `${viewportRect.x}%`,
                  top: `${viewportRect.y}%`,
                  width: `${viewportRect.width}%`,
                  height: `${viewportRect.height}%`,
                  border: 2,
                  borderColor: 'primary.main',
                  bgcolor: 'rgba(144, 202, 249, 0.2)',
                  pointerEvents: 'none',
                }}
              />
            </Box>

            {/* Zoom slider */}
            <Box sx={{ mt: 2, px: 1 }}>
              <Typography variant="caption" color="text.secondary">
                {t('diagram.view.zoom')}
              </Typography>
              <Slider
                value={zoom}
                min={0.5}
                max={4}
                step={0.1}
                onChange={(e, val) => setZoom(val)}
                valueLabelDisplay="auto"
                valueLabelFormat={(val) => `${Math.round(val * 100)}%`}
                size="small"
              />
            </Box>

            {/* Instructions */}
            <Box sx={{ mt: 'auto', pt: 2 }}>
              <Typography variant="caption" color="text.secondary" component="div">
                {t('diagram.hints.scroll')}
              </Typography>
              <Typography variant="caption" color="text.secondary" component="div">
                {t('diagram.hints.drag')}
              </Typography>
              <Typography variant="caption" color="text.secondary" component="div">
                {t('diagram.hints.miniMap')}
              </Typography>
              <Typography variant="caption" color="text.secondary" component="div">
                {t('diagram.hints.esc')}
              </Typography>
            </Box>
          </Box>
        </DialogContent>
      </Dialog>
    </>
  );
}

function ArchitectureDiagram() {
  const { t } = useTranslation();
  const [archSvg, setArchSvg] = useState('');
  const [flowSvg, setFlowSvg] = useState('');
  const [cicdSvg, setCicdSvg] = useState('');
  const [activeTab, setActiveTab] = useState(0);

  useEffect(() => {
    const renderDiagrams = async () => {
      try {
        const { svg: arch } = await mermaid.render('arch-diagram', architectureDiagram);
        setArchSvg(arch);
      } catch (e) {
        console.error('Failed to render architecture diagram:', e);
      }
      try {
        const { svg: flow } = await mermaid.render('flow-diagram', flowDiagram);
        setFlowSvg(flow);
      } catch (e) {
        console.error('Failed to render flow diagram:', e);
      }
      try {
        const { svg: cicd } = await mermaid.render('cicd-diagram', cicdDiagram);
        setCicdSvg(cicd);
      } catch (e) {
        console.error('Failed to render CI/CD diagram:', e);
      }
    };
    renderDiagrams();
  }, []);

  const tabs = [
    {
      label: t('diagram.tabs.infrastructure.label'),
      title: t('diagram.tabs.infrastructure.title'),
      description: t('diagram.tabs.infrastructure.description'),
      svg: archSvg,
    },
    {
      label: t('diagram.tabs.flow.label'),
      title: t('diagram.tabs.flow.title'),
      description: t('diagram.tabs.flow.description'),
      svg: flowSvg,
    },
    {
      label: t('diagram.tabs.cicd.label'),
      title: t('diagram.tabs.cicd.title'),
      description: t('diagram.tabs.cicd.description'),
      svg: cicdSvg,
    },
    {
      label: t('diagram.tabs.security.label'),
      title: t('diagram.tabs.security.title'),
      description: null,
      svg: null,
    },
  ];

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ px: 2, pt: 1 }}>
        <Typography variant="h5" gutterBottom>
          {t('diagram.view.heading')}
        </Typography>
      </Box>

      <Tabs
        value={activeTab}
        onChange={(e, newVal) => setActiveTab(newVal)}
        sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}
        variant="scrollable"
        scrollButtons="auto"
      >
        {tabs.map((tab, idx) => (
          <Tab key={idx} label={tab.label} />
        ))}
      </Tabs>

      <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
        {activeTab < 3 && (
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <Typography variant="h6" gutterBottom>
                {tabs[activeTab].title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {tabs[activeTab].description}
              </Typography>
              <Box sx={{ flex: 1, minHeight: 0 }}>
                {tabs[activeTab].svg ? (
                  <DiagramViewer svgContent={tabs[activeTab].svg} title={tabs[activeTab].title} />
                ) : (
                  <Paper sx={{ p: 4, textAlign: 'center', bgcolor: 'background.default' }}>
                    <Typography color="text.secondary">{t('diagram.view.loading')}</Typography>
                  </Paper>
                )}
              </Box>
            </CardContent>
          </Card>
        )}

        {activeTab === 3 && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                {t('diagram.tabs.security.title')}
              </Typography>
              <Box component="ul" sx={{ pl: 2 }}>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.hpkeLabel')}</strong> {t('diagram.security.hpkeText')}
                </Typography>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.e2eLabel')}</strong> {t('diagram.security.e2eText')}
                </Typography>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.browserLabel')}</strong> {t('diagram.security.browserText')}
                </Typography>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.keyLabel')}</strong> {t('diagram.security.keyText')}
                </Typography>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.chainLabel')}</strong> {t('diagram.security.chainText')}
                </Typography>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.biLabel')}</strong> {t('diagram.security.biText')}
                </Typography>
                <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                  <strong>{t('diagram.security.ztLabel')}</strong> {t('diagram.security.ztText')}
                </Typography>
                <Typography component="li" variant="body2">
                  <strong>{t('diagram.security.cicdLabel')}</strong> {t('diagram.security.cicdText')}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        )}
      </Box>
    </Box>
  );
}

export default ArchitectureDiagram;
