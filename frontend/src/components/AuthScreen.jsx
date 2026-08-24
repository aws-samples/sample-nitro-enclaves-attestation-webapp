import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Divider,
  Link,
} from '@mui/material';
import {
  Login as LoginIcon,
  Security as SecurityIcon,
  PersonAdd as SignUpIcon,
  VerifiedUser as VerifyIcon,
} from '@mui/icons-material';
import { signIn, signUp, confirmSignUp, resendVerificationCode, completeNewPasswordChallenge } from '../lib/cognitoAuth';

function AuthScreen({ onLogin }) {
  const { t } = useTranslation();
  const [tab, setTab] = useState(0); // 0 = Sign In, 1 = Sign Up, 2 = Verify
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [needsNewPassword, setNeedsNewPassword] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const user = await signIn(email, password);
      localStorage.setItem('nitro_user', JSON.stringify(user));
      onLogin(user);
    } catch (err) {
      if (err.code === 'NewPasswordRequired' || err.message === 'NEW_PASSWORD_REQUIRED') {
        setNeedsNewPassword(true);
        setError(null);
      } else if (err.message.includes('User does not exist')) {
        setError('No account found. Please sign up first.');
      } else if (err.message.includes('Incorrect username or password')) {
        setError('Incorrect email or password.');
      } else if (err.message.includes('User is not confirmed')) {
        setError('Please verify your email first.');
        setTab(2); // Switch to verify tab
      } else {
        setError(err.message || 'Login failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSignUp = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const result = await signUp(email, password);
      if (result.userConfirmed) {
        setSuccess('Account created! You can now sign in.');
        setTab(0);
      } else {
        setSuccess('Account created! Check your email for a verification code.');
        setTab(2); // Switch to verify tab
      }
    } catch (err) {
      if (err.message.includes('User already exists')) {
        setError('An account with this email already exists. Try signing in.');
      } else if (err.message.includes('Password did not conform')) {
        setError('Password must contain uppercase, lowercase, and numbers.');
      } else {
        setError(err.message || 'Sign up failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      await confirmSignUp(email, verificationCode);
      setSuccess('Email verified! You can now sign in.');
      setTab(0);
      setVerificationCode('');
    } catch (err) {
      if (err.message.includes('Invalid verification code')) {
        setError('Invalid code. Please check and try again.');
      } else if (err.message.includes('expired')) {
        setError('Code expired. Click "Resend Code" to get a new one.');
      } else {
        setError(err.message || 'Verification failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      await resendVerificationCode(email);
      setSuccess('Verification code sent! Check your email.');
    } catch (err) {
      setError(err.message || 'Failed to resend code');
    } finally {
      setLoading(false);
    }
  };

  const handleSetNewPassword = async (e) => {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirmNewPassword) {
      setError('Passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const user = await completeNewPasswordChallenge(newPassword);
      localStorage.setItem('nitro_user', JSON.stringify(user));
      onLogin(user);
    } catch (err) {
      setError(err.message || 'Failed to set new password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        bgcolor: 'background.default',
        p: 2,
      }}
    >
      <Card sx={{ maxWidth: 450, width: '100%' }}>
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ textAlign: 'center', mb: 3 }}>
            <SecurityIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
            <Typography variant="h4" component="h1" gutterBottom>
              {t('auth.screen.title')}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t('auth.screen.subtitle')}
            </Typography>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}
          {success && (
            <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
              {success}
            </Alert>
          )}

          {needsNewPassword ? (
            // New Password Form (admin-created users)
            <form onSubmit={handleSetNewPassword}>
              <Alert severity="info" sx={{ mb: 2 }}>
                <strong>{t('auth.screen.firstLoginLabel')}</strong> {t('auth.screen.firstLoginText')}
              </Alert>
              <TextField
                fullWidth label={t('auth.labels.newPassword')} type="password"
                value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
                margin="normal" required autoComplete="new-password"
                helperText={t('auth.helper.newPassword')}
              />
              <TextField
                fullWidth label={t('auth.labels.confirmNewPassword')} type="password"
                value={confirmNewPassword} onChange={(e) => setConfirmNewPassword(e.target.value)}
                margin="normal" required autoComplete="new-password"
              />
              <Button fullWidth type="submit" variant="contained" size="large"
                disabled={loading} sx={{ mt: 3 }}
                startIcon={loading ? <CircularProgress size={20} /> : <VerifyIcon />}
              >
                {loading ? t('auth.buttons.settingPassword') : t('auth.buttons.setNewPassword')}
              </Button>
              <Button fullWidth variant="text" size="small" sx={{ mt: 1 }}
                onClick={() => { setNeedsNewPassword(false); setNewPassword(''); setConfirmNewPassword(''); }}
              >
                {t('auth.buttons.backToLogin')}
              </Button>
            </form>
          ) : (
            <>
              <Tabs value={tab} onChange={(_, v) => { setTab(v); setError(null); setSuccess(null); }}
                variant="fullWidth" sx={{ mb: 2 }}
              >
                <Tab label={t('auth.tabs.signIn')} />
                <Tab label={t('auth.tabs.signUp')} />
                <Tab label={t('auth.tabs.verify')} />
              </Tabs>

              {/* Sign In Tab */}
              {tab === 0 && (
                <form onSubmit={handleLogin}>
                  <TextField
                    fullWidth label={t('auth.labels.email')} type="email"
                    value={email} onChange={(e) => setEmail(e.target.value)}
                    margin="normal" required autoComplete="email"
                  />
                  <TextField
                    fullWidth label={t('auth.labels.password')} type="password"
                    value={password} onChange={(e) => setPassword(e.target.value)}
                    margin="normal" required autoComplete="current-password"
                  />
                  <Button fullWidth type="submit" variant="contained" size="large"
                    disabled={loading} sx={{ mt: 3 }}
                    startIcon={loading ? <CircularProgress size={20} /> : <LoginIcon />}
                  >
                    {loading ? t('auth.buttons.signingIn') : t('auth.buttons.signIn')}
                  </Button>
                  <Box sx={{ mt: 2, textAlign: 'center' }}>
                    <Typography variant="body2" color="text.secondary">
                      {t('auth.prompts.noAccount')}{' '}
                      <Link component="button" variant="body2" onClick={() => setTab(1)}>
                        {t('auth.tabs.signUp')}
                      </Link>
                    </Typography>
                  </Box>
                </form>
              )}

              {/* Sign Up Tab */}
              {tab === 1 && (
                <form onSubmit={handleSignUp}>
                  <TextField
                    fullWidth label={t('auth.labels.email')} type="email"
                    value={email} onChange={(e) => setEmail(e.target.value)}
                    margin="normal" required autoComplete="email"
                  />
                  <TextField
                    fullWidth label={t('auth.labels.password')} type="password"
                    value={password} onChange={(e) => setPassword(e.target.value)}
                    margin="normal" required autoComplete="new-password"
                    helperText={t('auth.helper.password')}
                  />
                  <TextField
                    fullWidth label={t('auth.labels.confirmPassword')} type="password"
                    value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
                    margin="normal" required autoComplete="new-password"
                  />
                  <Button fullWidth type="submit" variant="contained" size="large"
                    disabled={loading} sx={{ mt: 3 }}
                    startIcon={loading ? <CircularProgress size={20} /> : <SignUpIcon />}
                  >
                    {loading ? t('auth.buttons.creatingAccount') : t('auth.buttons.createAccount')}
                  </Button>
                  <Box sx={{ mt: 2, textAlign: 'center' }}>
                    <Typography variant="body2" color="text.secondary">
                      {t('auth.prompts.haveAccount')}{' '}
                      <Link component="button" variant="body2" onClick={() => setTab(0)}>
                        {t('auth.tabs.signIn')}
                      </Link>
                    </Typography>
                  </Box>
                </form>
              )}

              {/* Verify Tab */}
              {tab === 2 && (
                <form onSubmit={handleVerify}>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    {t('auth.screen.verifyInfo')}
                  </Alert>
                  <TextField
                    fullWidth label={t('auth.labels.email')} type="email"
                    value={email} onChange={(e) => setEmail(e.target.value)}
                    margin="normal" required autoComplete="email"
                  />
                  <TextField
                    fullWidth label={t('auth.labels.verificationCode')} type="text"
                    value={verificationCode} onChange={(e) => setVerificationCode(e.target.value)}
                    margin="normal" required autoComplete="one-time-code"
                    placeholder="123456"
                    inputProps={{ maxLength: 6, style: { letterSpacing: '0.3em', textAlign: 'center', fontSize: '1.2rem' } }}
                  />
                  <Button fullWidth type="submit" variant="contained" size="large"
                    disabled={loading} sx={{ mt: 3 }}
                    startIcon={loading ? <CircularProgress size={20} /> : <VerifyIcon />}
                  >
                    {loading ? t('auth.buttons.verifying') : t('auth.buttons.verifyEmail')}
                  </Button>
                  <Button fullWidth variant="text" size="small" sx={{ mt: 1 }}
                    onClick={handleResendCode} disabled={loading || !email}
                  >
                    {t('auth.buttons.resendCode')}
                  </Button>
                </form>
              )}
            </>
          )}

          <Divider sx={{ mt: 3, mb: 1 }} />
          <Typography variant="caption" color="text.secondary" align="center" component="div">
            {t('auth.screen.footer')}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}

export default AuthScreen;
