import React, { useState, useEffect } from 'react';
import { useTranslation, Trans } from 'react-i18next';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Button,
  TextField,
  Grid,
  Alert,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  AppBar,
  Toolbar,
  IconButton,
  Stepper,
  Step,
  StepLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Verified as VerifiedIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Logout as LogoutIcon,
  ArrowBack as BackIcon,
  ArrowForward as NextIcon,
  Lock as LockIcon,
  Description as CertIcon,
  Architecture as ArchitectureIcon,
} from '@mui/icons-material';
import axios from 'axios';
import AuthScreen from './components/AuthScreen';
import ArchitectureDiagram from './components/ArchitectureDiagram';
import { getCurrentUser, signOut } from './lib/cognitoAuth';
import { verifyAttestationDocument } from './lib/attestationVerifier';
import { createSecureRequest } from './lib/hpkeEncryption';
import { parseX509Certificate } from './lib/x509Parser';

const API_BASE_URL = import.meta.env.VITE_API_ENDPOINT || '';

// Wizard step labels are resolved through i18n keys at render time.
const WIZARD_STEP_KEYS = [
  'wizard.steps.generate',
  'wizard.steps.verify',
  'wizard.steps.secureEcho',
];

function App() {
  const [user, setUser] = useState(null);
  const [authChecking, setAuthChecking] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const existingUser = await getCurrentUser();
        if (existingUser) setUser(existingUser);
      } catch (err) { /* no session */ }
      finally { setAuthChecking(false); }
    };
    checkAuth();
  }, []);

  if (authChecking) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!user) {
    return <AuthScreen onLogin={(u) => setUser(u)} />;
  }

  return <AuthenticatedApp user={user} onLogout={() => { signOut(); setUser(null); }} />;
}

function AuthenticatedApp({ user, onLogout }) {
  const { t } = useTranslation();
  const [activeStep, setActiveStep] = useState(0);
  const [showArchitecture, setShowArchitecture] = useState(false);
  const [attestationDoc, setAttestationDoc] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [nonce, setNonce] = useState('');
  const [userData, setUserData] = useState('');
  const [error, setError] = useState(null);
  const [enclavePublicKey, setEnclavePublicKey] = useState(null);
  const [secureMessage, setSecureMessage] = useState('');
  const [sendingMessage, setSendingMessage] = useState(false);
  const [secureResponse, setSecureResponse] = useState(null);
  const [certDialogOpen, setCertDialogOpen] = useState(false);
  const [selectedCert, setSelectedCert] = useState(null);

  const fetchAttestation = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/attestation`, {
        nonce: nonce || null,
        user_data: userData || null,
      }, {
        headers: user.idToken ? { Authorization: `Bearer ${user.idToken}` } : {},
      });
      setAttestationDoc(response.data);
    } catch (err) {
      setError('Failed to fetch attestation: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyAttestation = async () => {
    if (!attestationDoc) return;
    setVerifying(true);
    setError(null);
    try {
      const result = await verifyAttestationDocument(attestationDoc.attestation_document, nonce || null, userData || null);
      setVerificationResult(result);
      if (result.publicKey) setEnclavePublicKey(result.publicKey);
    } catch (err) {
      setError('Client-side verification failed: ' + err.message);
    } finally {
      setVerifying(false);
    }
  };

  const sendSecureMessage = async () => {
    if (!enclavePublicKey || !secureMessage) return;
    setSendingMessage(true);
    setError(null);
    setSecureResponse(null);
    try {
      const { requestPayload, responseDecryptor } = await createSecureRequest(enclavePublicKey, secureMessage);
      const response = await axios.post(`${API_BASE_URL}/api/decrypt/hpke`, requestPayload, {
        headers: user.idToken ? { Authorization: `Bearer ${user.idToken}` } : {},
      });
      const iv = response.data.response_iv || response.data.iv;
      const ct = response.data.encrypted_response || response.data.ciphertext;
      if (iv && ct) {
        const decryptedResponse = await responseDecryptor(iv, ct);
        setSecureResponse({ decrypted: decryptedResponse, raw: response.data });
      } else {
        setSecureResponse({ decrypted: null, raw: response.data, note: 'Enclave acknowledged (no encrypted response)' });
      }
    } catch (err) {
      setError('Failed to send secure message: ' + err.message);
    } finally {
      setSendingMessage(false);
    }
  };

  const generateRandomNonce = () => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    setNonce(Array.from(randomBytes, b => b.toString(16).padStart(2, '0')).join(''));
  };

  const handleNext = () => {
    if (activeStep === 0 && attestationDoc) {
      // Auto-verify when moving to step 2
      if (!verificationResult) verifyAttestation();
      setActiveStep(1);
    } else if (activeStep === 1 && verificationResult?.verified) {
      setActiveStep(2);
    }
  };

  const handleBack = () => {
    setActiveStep((prev) => Math.max(0, prev - 1));
  };

  const canGoNext = () => {
    if (activeStep === 0) return !!attestationDoc;
    if (activeStep === 1) return !!verificationResult?.verified;
    return false;
  };

  // Parse a DER certificate for display
  const parseCertForDisplay = (certBytes, index, label) => {
    if (!certBytes) return null;
    let hex = '';
    if (certBytes instanceof Uint8Array) {
      hex = Array.from(certBytes, b => b.toString(16).padStart(2, '0')).join('');
    } else if (typeof certBytes === 'string') {
      hex = certBytes;
    }
    return {
      index,
      label: label || `Certificate ${index + 1}`,
      size: certBytes.length || hex.length / 2,
      hex: hex.substring(0, 200) + (hex.length > 200 ? '...' : ''),
      fullHex: hex,
      pem: formatAsPem(certBytes),
    };
  };

  const formatAsPem = (derBytes) => {
    let b64;
    if (derBytes instanceof Uint8Array) {
      b64 = btoa(String.fromCharCode(...derBytes));
    } else if (typeof derBytes === 'string') {
      // Already hex? Try to convert
      try {
        const bytes = new Uint8Array(derBytes.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        b64 = btoa(String.fromCharCode(...bytes));
      } catch {
        b64 = derBytes;
      }
    } else {
      return 'Unable to format';
    }
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
  };

  const getCertificateChain = () => {
    if (!verificationResult?.attestationData) return [];
    const chain = [];
    const data = verificationResult.attestationData;

    // Signing certificate (leaf)
    if (data.certificate) {
      chain.push(parseCertForDisplay(data.certificate, 0, '🔏 Signing Certificate (Leaf)'));
    }

    // CA bundle - AWS Nitro orders as root first, then intermediates
    // The root cert is the one where Subject === Issuer (self-signed)
    if (data.cabundle && Array.isArray(data.cabundle)) {
      const total = data.cabundle.length;
      data.cabundle.forEach((cert, i) => {
        // Try to detect root (first cert is typically root in AWS Nitro cabundle)
        let label;
        if (i === 0) {
          label = '🏛️ Root CA (AWS Nitro)';
        } else if (i === total - 1) {
          label = `🔗 Intermediate CA (closest to leaf)`;
        } else {
          label = `🔗 Intermediate CA ${i}`;
        }
        chain.push(parseCertForDisplay(cert, i + 1, label));
      });
    }

    return chain.filter(Boolean);
  };

  return (
    <>
      <AppBar position="static" sx={{ mb: 3 }}>
        <Toolbar>
          <SecurityIcon sx={{ mr: 2 }} />
          <Typography variant="h6" sx={{ flexGrow: 1 }}>{t('app.header.title')}</Typography>
          <Button
            color="inherit"
            startIcon={<ArchitectureIcon />}
            onClick={() => setShowArchitecture(!showArchitecture)}
            variant={showArchitecture ? 'outlined' : 'text'}
            sx={{ mr: 2, textTransform: 'none' }}
          >
            {showArchitecture ? t('app.nav.backToApp') : t('app.nav.architecture')}
          </Button>
          <Typography variant="body2" sx={{ mr: 2 }}>{user.email}</Typography>
          <IconButton color="inherit" onClick={onLogout} title={t('app.nav.signOut')}><LogoutIcon /></IconButton>
        </Toolbar>
      </AppBar>

      {/* Architecture Documentation View */}
      {showArchitecture && (
        <Box sx={{ height: 'calc(100vh - 80px)', overflow: 'hidden' }}>
          <ArchitectureDiagram />
        </Box>
      )}

      {/* Main Wizard View */}
      {!showArchitecture && (
      <Container maxWidth="lg" sx={{ py: 2 }}>
        {/* Stepper */}
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {WIZARD_STEP_KEYS.map((stepKey) => (
            <Step key={stepKey}>
              <StepLabel>{t(stepKey)}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>{error}</Alert>
        )}

        {/* Step 1: Generate Attestation Document */}
        {activeStep === 0 && (
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                <RefreshIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                {t('wizard.step1.title')}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                {t('wizard.step1.intro')}
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={5}>
                  <TextField fullWidth label={t('wizard.step1.nonceLabel')} value={nonce}
                    onChange={(e) => setNonce(e.target.value)} placeholder={t('wizard.step1.noncePlaceholder')} />
                </Grid>
                <Grid item xs={12} sm={3}>
                  <Button variant="outlined" onClick={generateRandomNonce} sx={{ height: '56px' }} fullWidth>
                    {t('wizard.step1.randomNonce')}
                  </Button>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <TextField fullWidth label={t('wizard.step1.userDataLabel')} value={userData}
                    onChange={(e) => setUserData(e.target.value)} placeholder={t('wizard.step1.userDataPlaceholder')} />
                </Grid>
                <Grid item xs={12}>
                  <Button variant="contained" onClick={fetchAttestation} disabled={loading} size="large"
                    startIcon={loading ? <CircularProgress size={20} /> : <RefreshIcon />}>
                    {loading ? t('wizard.step1.fetching') : t('wizard.step1.fetch')}
                  </Button>
                </Grid>
              </Grid>

              {/* Document viewer */}
              {attestationDoc && (
                <Paper sx={{ p: 3, bgcolor: 'rgba(102,187,106,0.08)', border: '1px solid rgba(102,187,106,0.3)', borderRadius: 2 }}>
                  <Typography variant="h6" gutterBottom color="success.main">
                    {t('wizard.step1.received')}
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">{t('wizard.step1.size')}</Typography>
                      <Typography variant="body1">{t('common.unit.bytes', { n: attestationDoc.size_bytes })}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">{t('wizard.step1.environment')}</Typography>
                      <Typography variant="body1">{attestationDoc.environment}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Accordion>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="body2">{t('wizard.step1.rawBase64')}</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Paper sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.3)', maxHeight: 200, overflow: 'auto' }}>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', color: '#e0e0e0', fontSize: '0.65rem' }}>
                              {attestationDoc.attestation_document}
                            </Typography>
                          </Paper>
                        </AccordionDetails>
                      </Accordion>
                    </Grid>
                  </Grid>
                </Paper>
              )}
            </CardContent>
          </Card>
        )}

        {/* Step 2: Attestation Verification */}
        {activeStep === 1 && (
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                <VerifiedIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                {t('wizard.step2.title')}
                <Chip label={t('wizard.step2.clientSide')} size="small" sx={{ ml: 1 }} variant="outlined" />
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                {t('wizard.step2.intro')}
              </Typography>

              {verifying && (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <CircularProgress size={48} />
                  <Typography sx={{ mt: 2 }}>{t('wizard.step2.verifying')}</Typography>
                </Box>
              )}

              {!verifying && !verificationResult && (
                <Button variant="contained" onClick={verifyAttestation} size="large">
                  {t('wizard.step2.verifyNow')}
                </Button>
              )}

              {verificationResult && (
                <>
                  {/* Status */}
                  <Box sx={{ mb: 3 }}>
                    <Chip
                      label={verificationResult.verified ? t('wizard.step2.verified') : t('wizard.step2.failed')}
                      color={verificationResult.verified ? 'success' : 'error'}
                      icon={verificationResult.verified ? <VerifiedIcon /> : <ErrorIcon />}
                      size="large" sx={{ fontSize: '1rem', py: 2.5 }}
                    />
                    {enclavePublicKey && (
                      <Chip label={t('wizard.step2.publicKeyExtracted')} color="info" size="small" sx={{ ml: 1 }} />
                    )}
                  </Box>

                  {verificationResult.error && (
                    <Alert severity="error" sx={{ mb: 2 }}>{verificationResult.error}</Alert>
                  )}

                  {/* Signed inputs echoed back in the attestation document */}
                  {verificationResult.attestationData && (
                    <Paper sx={{ p: 2, mb: 2, bgcolor: 'rgba(255,255,255,0.04)' }}>
                      <Typography variant="subtitle1" sx={{ mb: 1 }}>{t('wizard.step2.signedInputs')}</Typography>
                      {[
                        { label: t('wizard.step2.nonce'), input: nonce, signed: verificationResult.attestationData.nonceText },
                        { label: t('wizard.step2.userData'), input: userData, signed: verificationResult.attestationData.userDataText },
                      ].map(({ label, input, signed }) => (
                        <Box key={label} sx={{ mb: 1 }}>
                          <Typography variant="subtitle2">
                            {label}
                            {input ? (
                              <Chip
                                label={signed === input ? t('wizard.step2.match') : t('wizard.step2.noMatch')}
                                size="small"
                                color={signed === input ? 'success' : 'error'}
                                sx={{ ml: 1 }}
                              />
                            ) : (
                              <Chip label={t('wizard.step2.notSent')} size="small" sx={{ ml: 1 }} />
                            )}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {t('wizard.step2.sent')} <code>{input || t('common.value.none')}</code>
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {t('wizard.step2.inDocument')} <code>{signed ?? t('common.value.none')}</code>
                          </Typography>
                        </Box>
                      ))}
                    </Paper>
                  )}

                  {/* Verification Steps */}
                  {verificationResult.verificationSteps && (
                    <Accordion defaultExpanded sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">{t('wizard.step2.stepsTitle', { n: verificationResult.verificationSteps.length })}</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {verificationResult.verificationSteps.map((step, index) => (
                          <Paper key={index} sx={{ p: 2, mb: 1, bgcolor: step.status === 'success' ? 'rgba(102,187,106,0.12)' : step.status === 'failed' ? 'rgba(244,67,54,0.12)' : step.status === 'warning' ? 'rgba(255,167,38,0.12)' : 'rgba(255,255,255,0.04)' }}>
                            <Typography variant="subtitle2">
                              {step.step}
                              <Chip label={step.status} size="small" sx={{ ml: 1 }}
                                color={step.status === 'success' ? 'success' : step.status === 'failed' ? 'error' : step.status === 'warning' ? 'warning' : 'default'} />
                            </Typography>
                            <Typography variant="body2" color="text.secondary">{step.details}</Typography>
                          </Paper>
                        ))}
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* Certificate Chain - Clickable */}
                  {verificationResult.attestationData && (
                    <Accordion defaultExpanded sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          {t('wizard.step2.certChainTitle', { n: getCertificateChain().length })}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {t('wizard.step2.certChainHint')}
                        </Typography>
                        <List sx={{ bgcolor: 'rgba(0,0,0,0.15)', borderRadius: 1 }}>
                          {getCertificateChain().map((cert, idx) => (
                            <React.Fragment key={idx}>
                              {idx > 0 && <Divider />}
                              <ListItem disablePadding>
                                <ListItemButton onClick={() => { setSelectedCert(cert); setCertDialogOpen(true); }}>
                                  <ListItemIcon>
                                    <CertIcon color={idx === 0 ? 'primary' : idx === getCertificateChain().length - 1 ? 'success' : 'secondary'} />
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={cert.label}
                                    secondary={t('common.unit.bytesDerEncoded', { n: cert.size })}
                                  />
                                  <Chip label={t('common.action.view')} size="small" variant="outlined" />
                                </ListItemButton>
                              </ListItem>
                            </React.Fragment>
                          ))}
                        </List>
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* PCR Values */}
                  {verificationResult.attestationData?.pcrs && (
                    <Accordion sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">{t('wizard.step2.pcrTitle')}</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <TableContainer component={Paper} sx={{ bgcolor: 'rgba(0,0,0,0.2)' }}>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>{t('wizard.step2.pcr')}</TableCell>
                                <TableCell>{t('wizard.step2.pcrValue')}</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {Object.entries(verificationResult.attestationData.pcrs).map(([pcrNum, pcrValue]) => (
                                <TableRow key={pcrNum}>
                                  <TableCell><strong>{t('wizard.step2.pcr')}{pcrNum}</strong></TableCell>
                                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }}>{pcrValue}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* Attestation Metadata */}
                  {verificationResult.attestationData && (
                    <Accordion sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">{t('wizard.step2.metadataTitle')}</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={1}>
                          <Grid item xs={12} sm={6}>
                            <Typography variant="body2"><strong>{t('wizard.step2.moduleId')}</strong> {verificationResult.attestationData.moduleId}</Typography>
                          </Grid>
                          <Grid item xs={12} sm={6}>
                            <Typography variant="body2"><strong>{t('wizard.step2.timestamp')}</strong> {
                              // NSM attestation timestamp is milliseconds since UNIX epoch
                              new Date(verificationResult.attestationData.timestamp).toLocaleString(undefined, { timeZoneName: 'short' })
                            }</Typography>
                          </Grid>
                          <Grid item xs={12} sm={6}>
                            <Typography variant="body2"><strong>{t('wizard.step2.digest')}</strong> {verificationResult.attestationData.digest}</Typography>
                          </Grid>
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        )}

        {/* Step 3: Secure Message Echo */}
        {activeStep === 2 && (
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                <LockIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                {t('wizard.step3.title')}
              </Typography>
              <Alert severity="info" sx={{ mb: 3 }}>
                <Trans i18nKey="wizard.step3.info" components={{ b: <strong /> }} />
              </Alert>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12}>
                  <TextField fullWidth multiline rows={3}
                    label={t('wizard.step3.messageLabel')}
                    value={secureMessage} onChange={(e) => setSecureMessage(e.target.value)}
                    placeholder={t('wizard.step3.messagePlaceholder')} />
                </Grid>
                <Grid item xs={12}>
                  <Button variant="contained" color="secondary" onClick={sendSecureMessage}
                    disabled={sendingMessage || !secureMessage} size="large"
                    startIcon={sendingMessage ? <CircularProgress size={20} /> : <LockIcon />}>
                    {sendingMessage ? t('wizard.step3.sending') : t('wizard.step3.send')}
                  </Button>
                </Grid>
              </Grid>

              {secureResponse && (
                <Paper sx={{ p: 3, bgcolor: 'rgba(102,187,106,0.08)', border: '1px solid rgba(102,187,106,0.3)', borderRadius: 2 }}>
                  <Typography variant="h6" gutterBottom color="success.main">{t('wizard.step3.responseTitle')}</Typography>
                  {secureResponse.decrypted && (
                    <Alert severity="success" sx={{ mb: 2 }}>
                      <strong>{t('wizard.step3.decryptedLabel')}</strong> {secureResponse.decrypted}
                    </Alert>
                  )}
                  {secureResponse.note && (
                    <Alert severity="info" sx={{ mb: 2 }}>{secureResponse.note}</Alert>
                  )}
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="body2">{t('wizard.step3.rawPayload')}</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Paper sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.3)' }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: '#e0e0e0', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                          {JSON.stringify(secureResponse.raw, null, 2)}
                        </Typography>
                      </Paper>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              )}
            </CardContent>
          </Card>
        )}

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
          <Button onClick={handleBack} disabled={activeStep === 0} startIcon={<BackIcon />} variant="outlined" size="large">
            {t('wizard.nav.back')}
          </Button>
          <Button onClick={handleNext} disabled={!canGoNext()} endIcon={<NextIcon />} variant="contained" size="large">
            {activeStep === 0 ? t('wizard.nav.verifyNext') : activeStep === 1 ? t('wizard.nav.secureNext') : t('wizard.nav.done')}
          </Button>
        </Box>
      </Container>
      )}

      {/* Certificate Detail Dialog */}
      <Dialog open={certDialogOpen} onClose={() => setCertDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedCert?.label}
        </DialogTitle>
        <DialogContent>
          {selectedCert && (() => {
            // Parse the raw DER bytes to get certificate details
            const rawBytes = verificationResult?.attestationData && (() => {
              const data = verificationResult.attestationData;
              if (selectedCert.index === 0) return data.certificate;
              if (data.cabundle) return data.cabundle[selectedCert.index - 1];
              return null;
            })();
            const certDetails = rawBytes ? parseX509Certificate(rawBytes) : null;

            return (
              <>
                {/* Parsed Certificate Details */}
                {certDetails && !certDetails.error && (
                  <Box sx={{ mb: 3 }}>
                    <TableContainer component={Paper} sx={{ bgcolor: 'rgba(0,0,0,0.15)' }}>
                      <Table size="small">
                        <TableBody>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold', width: '30%' }}>{t('cert.field.version')}</TableCell>
                            <TableCell>{certDetails.version}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.serialNumber')}</TableCell>
                            <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{certDetails.serialNumber}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.subject')}</TableCell>
                            <TableCell>{certDetails.subject}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.issuer')}</TableCell>
                            <TableCell>{certDetails.issuer}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.validFrom')}</TableCell>
                            <TableCell>{certDetails.validity.notBefore?.toLocaleString() || t('common.value.na')}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.validUntil')}</TableCell>
                            <TableCell>{certDetails.validity.notAfter?.toLocaleString() || t('common.value.na')}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.signatureAlgorithm')}</TableCell>
                            <TableCell>{certDetails.signatureAlgorithm}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.publicKey')}</TableCell>
                            <TableCell>{t('cert.field.publicKeyValue', { algorithm: certDetails.publicKeyAlgorithm, bits: certDetails.publicKeySize })}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 'bold' }}>{t('cert.field.size')}</TableCell>
                            <TableCell>{t('common.unit.bytesDer', { n: selectedCert.size })}</TableCell>
                          </TableRow>
                        </TableBody>
                      </Table>
                    </TableContainer>

                    {/* Extensions */}
                    {certDetails.extensions.length > 0 && (
                      <Accordion sx={{ mt: 2 }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle2">{t('cert.ext.title', { n: certDetails.extensions.length })}</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>{t('cert.ext.name')}</TableCell>
                                <TableCell>{t('cert.ext.critical')}</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {certDetails.extensions.map((ext, i) => (
                                <TableRow key={i}>
                                  <TableCell>{ext.name}</TableCell>
                                  <TableCell>
                                    <Chip label={ext.critical ? t('cert.ext.yes') : t('cert.ext.no')} size="small"
                                      color={ext.critical ? 'warning' : 'default'} variant="outlined" />
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </AccordionDetails>
                      </Accordion>
                    )}
                  </Box>
                )}

                {certDetails?.error && (
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    {certDetails.error}
                  </Alert>
                )}

                {/* PEM Format */}
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle2">{t('cert.format.pem')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Paper sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.3)', maxHeight: 250, overflow: 'auto' }}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: '#e0e0e0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {selectedCert.pem}
                      </Typography>
                    </Paper>
                  </AccordionDetails>
                </Accordion>
              </>
            );
          })()}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            if (selectedCert?.pem) navigator.clipboard.writeText(selectedCert.pem);
          }}>
            {t('cert.action.copyPem')}
          </Button>
          <Button onClick={() => setCertDialogOpen(false)} variant="contained">{t('common.action.close')}</Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export default App;
