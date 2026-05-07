import React from 'react'
import { useAuth } from 'react-oidc-context'
import { Loader, Shield } from 'lucide-react'

export default function LoginPage() {
    const auth = useAuth()

    return (
        <>
            <style>{`
                .login-container {
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    background-color: #002A4C;
                    font-family: 'Open Sans', sans-serif;
                }
                .login-card {
                    background: white;
                    padding: 60px;
                    border-radius: 48px;
                    width: 100%;
                    max-width: 460px;
                    text-align: center;
                    box-shadow: none;
                    border: none;
                }
                .logo-box {
                    display: flex;
                    justify-content: center;
                    margin-bottom: 30px;
                }
                .logo-square {
                    width: 96px;
                    height: 96px;
                    background: #002A4C;
                    border-radius: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .login-h1 {
                    font-size: 40px;
                    font-weight: 800;
                    color: #002A4C;
                    margin-bottom: 10px;
                    letter-spacing: -1px;
                }
                .login-p {
                    font-size: 10px;
                    font-weight: 700;
                    color: #94A3B8;
                    letter-spacing: 2px;
                    text-transform: uppercase;
                    margin-bottom: 40px;
                }
                .login-btn {
                    width: 100%;
                    padding: 20px;
                    background: #002A4C;
                    color: white;
                    border: none;
                    border-radius: 16px;
                    font-weight: 700;
                    font-size: 12px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 12px;
                    transition: all 0.2s;
                    letter-spacing: 1px;
                }
                .login-btn:hover { background: #003a6a; }
                .login-btn:active { transform: scale(0.98); }
                .login-footer {
                    margin-top: 60px;
                    padding-top: 30px;
                    border-top: 1px solid #f1f5f9;
                }
                .footer-text { 
                    font-size: 10px; 
                    color: #CBD5E1; 
                    font-weight: 800; 
                    letter-spacing: 3px; 
                    text-transform: uppercase; 
                }
                .error-box {
                    margin-top: 20px;
                    padding: 12px;
                    background: #FEF2F2;
                    border: 1px solid #FEE2E2;
                    color: #DC2626;
                    border-radius: 12px;
                    font-size: 10px;
                    font-weight: 600;
                    text-transform: uppercase;
                }
            `}</style>
            <div className="login-container">
                <div className="login-card">
                    <div className="logo-box">
                        <div className="logo-square">
                            <Shield size={48} color="white" />
                        </div>
                    </div>
                    <h1 className="login-h1">Centinela</h1>
                    <p className="login-p">SISTEMA INTELIGENTE DE MONITOREO Y SEGURIDAD</p>

                    <button onClick={() => void auth.signinRedirect()} disabled={auth.isLoading} className="login-btn">
                        {auth.isLoading ? <Loader className="animate-spin" size={20} /> : <Shield size={18} fill="white" className="opacity-80" />}
                        <span>{auth.isLoading ? 'CONECTANDO...' : 'INICIAR SESIÓN CON CASMARTS ID'}</span>
                    </button>

                    <div style={{ marginTop: '25px' }}>
                        <a href="https://arquitectura.casmart.internal/if/flow/password-recovery/"
                            style={{ fontSize: '11px', color: '#002A4C80', textDecoration: 'none', fontWeight: '700' }}>
                            ¿Olvidaste tu contraseña?
                        </a>
                    </div>

                    {auth.error && (
                        <div className="error-box">
                            Auth Error: {auth.error.message}
                        </div>
                    )}

                    <div className="login-footer">
                        <p className="footer-text">POWERED BY CASMARTS AI CORE</p>
                    </div>
                </div>
            </div>
        </>
    )
}
