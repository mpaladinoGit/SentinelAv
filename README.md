# SentinelAV Security Suite (Windows Desktop)

Suíte de segurança, antivírus multicamada, heurística PE, proteção web e quarentena criptografada para Windows 10/11.

## Principais Funcionalidades

- **Motor de Detecção Multicamada**:
  - **Assinaturas SHA-256** (`SQLite` indexado com milhares de hashes de malware).
  - **Regras Estilo YARA / Padrões Binários**: Detecção de *Ransomware*, *Keyloggers*, *Reverse Shells*, *Credential Dumpers* e *PowerShell Encoded Payloads*.
  - **Heurística Estática PE (`.exe`, `.dll`, `.sys`, `.scr`)**: Análise de entropia de seções (detecção de *packers*/criptografia) e inspeção da Tabela de Importação (`IAT`) para APIs de injeção de processo (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
  - **Verificação de Assinatura Digital Authenticode**: Validação via WinVerifyTrust / PowerShell para diferenciar binários oficiais assinados de executáveis suspeitos.
- **Escudo em Tempo Real & Memória RAM**:
  - Monitoramento contínuo das pastas críticas (`Downloads`, `Temp`, `Startup`) e inspeção de processos ativos na memória RAM (`psutil`).
- **Proteção Web, Navegadores & Rede**:
  - Verificador de links e domínios Anti-Phishing (OpenPhish / URLhaus + heurística de *typosquatting* bancário).
  - Inspeção de conexões TCP ativas contra IPs de Botnet/C2 (Feodo Tracker) e portas de RAT/mineração.
  - Auditoria de extensões de navegadores (Chrome, Edge, Brave) e integridade do arquivo `hosts` do Windows.
- **Cofre de Quarentena Criptografado**: Isolamento seguro com cifra `XOR-256` e opção de restauração com *Whitelist*.
- **Atualização Online Manual e Automática Semanal**: Sincronização sob demanda com feeds públicos de inteligência de ameaças (MalwareBazaar, URLhaus, OpenPhish, Feodo Tracker) + agendamento semanal automático.

## Como Executar a partir do Código-Fonte

```bash
pip install -r requirements.txt
python main.py
```

## Como Gerar o Instalador Independente (`.exe`)

1. Gere o pacote autônomo com `PyInstaller`:
   ```bash
   pyinstaller SentinelAV.spec
   ```
2. Compile o instalador único com o **Inno Setup 6**:
   ```bash
   ISCC.exe SentinelAV_Setup.iss
   ```
