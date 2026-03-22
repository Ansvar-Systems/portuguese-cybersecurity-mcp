/**
 * Seed the CNCS database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Includes representative CNCS (Centro Nacional de Ciberseguranca) cybersecurity
 * guidelines, NIS2 guidance, and sample security advisories in Portuguese.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force   # drop and recreate
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CNCS_DB_PATH"] ?? "data/cncs.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "qnrcs",
    name: "Quadro Nacional de Referencia para a Ciberseguranca (QNRCS)",
    name_en: "National Cybersecurity Reference Framework",
    description: "O QNRCS e o quadro de referencia nacional para a ciberseguranca em Portugal, alinhado com o NIST Cybersecurity Framework e adaptado ao contexto legal e regulatorio portugues, incluindo a Diretiva NIS2 e o RGPD.",
    document_count: 28,
  },
  {
    id: "nis2-pt",
    name: "Implementacao da Diretiva NIS2 em Portugal",
    name_en: "NIS2 Directive Implementation in Portugal",
    description: "Orientacoes para a implementacao da Diretiva NIS2 (UE 2022/2555) em Portugal. Inclui a transposicao legislativa, requisitos de notificacao de incidentes e supervisao pelo CNCS.",
    document_count: 12,
  },
  {
    id: "cncs-guidelines",
    name: "Guias Tecnicos CNCS",
    name_en: "CNCS Technical Guides",
    description: "Guias tecnicos publicados pelo CNCS sobre temas especificos de ciberseguranca: gestao de vulnerabilidades, seguranca de redes, autenticacao, criptografia e resposta a incidentes.",
    document_count: 35,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);
for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}
console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "CNCS-GT-2023-01",
    title: "Gestao de Vulnerabilidades — Guia para Organizacoes",
    title_en: "Vulnerability Management — Guide for Organisations",
    date: "2023-04-20",
    type: "technical_guideline",
    series: "CNCS",
    summary: "Guia pratico para implementacao de um processo de gestao de vulnerabilidades nas organizacoes. Abrange identificacao, classificacao com CVSS, priorizacao, remediacao e monitorizacao de vulnerabilidades.",
    full_text: "A gestao de vulnerabilidades e um dos processos fundamentais da ciberseguranca organizacional. Este guia descreve a implementacao de um processo sistematico.\n\nIdentificacao de vulnerabilidades:\n- Scanners automaticos (OpenVAS, Nessus, Qualys)\n- Analise de dependencias em projetos de software (OWASP Dependency Check, Snyk)\n- Feeds de inteligencia de ameacas (CNCS, ENISA, MITRE CVE)\n- Testes de penetracao regulares\n\nClassificacao com CVSS v3.1:\n- Critico (9.0-10.0): remediar imediatamente\n- Alto (7.0-8.9): remediar com urgencia\n- Medio (4.0-6.9): remediar no ciclo normal\n- Baixo (0.1-3.9): remediar conforme recursos\n\nPrivorizacao: Para alem do CVSS, considerar EPSS (probabilidade de exploracao), existencia de exploit publico, criticidade do sistema e exposicao a internet.\n\nSLAs de remediacao recomendados: Critico 24h, Alto 7 dias, Medio 30 dias, Baixo 90 dias.\n\nMonitorizacao: Medir Mean Time to Remediate (MTTR), numero de vulnerabilidades em aberto por severidade e cumprimento de SLAs.",
    topics: JSON.stringify(["vulnerabilidades", "CVSS", "gestao de riscos", "patches", "seguranca"]),
    status: "current",
  },
  {
    reference: "CNCS-GT-2023-02",
    title: "Seguranca em Ambientes de Nuvem — Guia de Boas Praticas",
    title_en: "Cloud Security — Best Practices Guide",
    date: "2023-07-15",
    type: "technical_guideline",
    series: "CNCS",
    summary: "Guia de boas praticas para a seguranca em ambientes de computacao em nuvem (IaaS, PaaS, SaaS). Abrange gestao de identidades, controlo de acesso, encriptacao, monitorizacao e conformidade com o RGPD.",
    full_text: "A adocao de servicos de nuvem trouxe novos desafios de seguranca. Este guia aborda as principais consideracoes para a seguranca em nuvem.\n\nModelo de responsabilidade partilhada:\nOs fornecedores de nuvem sao responsaveis pela seguranca da infraestrutura ('security of the cloud'). Os clientes sao responsaveis pela seguranca dos dados e configuracoes ('security in the cloud').\n\nGestao de identidades e acessos (IAM):\n- Implementar o principio do menor privilegio\n- Utilizar autenticacao multifator (MFA) para todas as contas\n- Revisar regularmente as permissoes e remover acessos desnecessarios\n- Usar identidades geridas sempre que possivel\n\nEncriptacao:\n- Encriptar dados em repouso e em transito\n- Gerir as chaves de encriptacao com servicos dedicados (KMS)\n- Considerar BYOK (Bring Your Own Key) para dados sensiveis\n\nMonitorizacao e detecao:\n- Ativar logging centralizado de todos os recursos\n- Configurar alertas para atividades suspeitas\n- Integrar com SIEM para correlacao de eventos\n\nConformidade RGPD:\n- Verificar localizacao geografica dos dados (residencia de dados)\n- Avaliar clausulas contratuais padrao para transferencias internacionais\n- Documentar o inventario de tratamentos de dados na nuvem",
    topics: JSON.stringify(["nuvem", "cloud security", "IAM", "encriptacao", "RGPD", "monitoramento"]),
    status: "current",
  },
  {
    reference: "CNCS-GT-2022-05",
    title: "Autenticacao Forte e Gestao de Identidades",
    title_en: "Strong Authentication and Identity Management",
    date: "2022-09-10",
    type: "technical_guideline",
    series: "CNCS",
    summary: "Guia sobre implementacao de autenticacao forte (MFA) e gestao segura de identidades. Abrange tecnologias de autenticacao, politicas de passwords, SSO e privileged access management.",
    full_text: "A autenticacao fraca e uma das principais causas de compromisso de contas e violacoes de dados. Este guia apresenta as melhores praticas para autenticacao forte.\n\nAutenticacao Multifator (MFA):\nA MFA exige dois ou mais fatores: algo que sabe (password), algo que tem (token, smartphone), algo que e (biometria). O CNCS recomenda MFA para todos os sistemas com acesso a dados sensiveis ou acesso privilegiado.\n\nTecnologias recomendadas:\n- TOTP (OATH-TOTP/HOTP) com apps como Google Authenticator, Microsoft Authenticator\n- Chaves de seguranca FIDO2/WebAuthn (resistentes a phishing)\n- Certificados digitais (PKI)\n- SMS como segundo fator e aceitavel mas menos seguro (vulneravel a SIM swapping)\n\nPolitica de passwords:\n- Comprimento minimo: 12 caracteres (16+ para contas privilegiadas)\n- Verificar contra listas de passwords comprometidas (HIBP API)\n- Nao impor rotacao periodica forcada (promove passwords fracas)\n- Permitir gestores de passwords\n\nPrivileged Access Management (PAM):\n- Contas privilegiadas separadas das contas normais\n- Just-in-time access para tarefas administrativas\n- Sessoes gravadas para auditoria\n- Revisao regular de acessos privilegiados",
    topics: JSON.stringify(["autenticacao", "MFA", "FIDO2", "passwords", "PAM", "identidades"]),
    status: "current",
  },
  {
    reference: "CNCS-NIS2-2023-01",
    title: "Guia de Implementacao da Diretiva NIS2 em Portugal",
    title_en: "NIS2 Directive Implementation Guide in Portugal",
    date: "2023-10-17",
    type: "sector_guide",
    series: "NIS2",
    summary: "Guia pratico para a implementacao da Diretiva NIS2 em Portugal. Abrange categorias de entidades, requisitos de seguranca (artigo 21), obrigacoes de notificacao (artigo 23) e o regime sancionatorio.",
    full_text: "A Diretiva NIS2 (UE 2022/2555) entrou em vigor em janeiro de 2023 e deve ser transposta para o direito nacional ate outubro de 2024.\n\nCategorizacao de entidades:\n- Entidades Essenciais: energia, transportes, banca, infraestruturas de mercados financeiros, saude, agua potavel, aguas residuais, infraestrutura digital, gestao de servicos TIC, administracao publica, espaco\n- Entidades Importantes: servicos postais, gestao de residuos, fabricacao de produtos quimicos, producao alimentar, fabricacao, fornecedores de servicos digitais\n\nRequisitos de seguranca (Artigo 21):\n1. Politicas de analise de risco e seguranca dos sistemas de informacao\n2. Tratamento de incidentes\n3. Continuidade de atividade (backup, recuperacao de desastres)\n4. Seguranca da cadeia de abastecimento\n5. Aquisicao, desenvolvimento e manutencao de sistemas\n6. Gestao de vulnerabilidades\n7. Politicas e procedimentos de avaliacao da eficacia\n8. Praticas basicas de ciberhigiene e formacao\n9. Politicas de criptografia\n10. Seguranca dos recursos humanos\n11. Autenticacao multifator ou autenticacao continua\n\nNotificacao de incidentes (Artigo 23): Alerta precoce 24h, notificacao 72h, relatorio final 1 mes.\n\nRegime sancionatorio: Entidades essenciais ate 10M EUR ou 2% do volume de negocios mundial. Entidades importantes ate 7M EUR ou 1,4%.",
    topics: JSON.stringify(["NIS2", "diretiva", "requisitos seguranca", "notificacao incidentes", "sancoes", "Portugal"]),
    status: "current",
  },
  {
    reference: "CNCS-GT-2023-03",
    title: "Resposta a Incidentes de Ciberseguranca — Guia Pratico",
    title_en: "Cybersecurity Incident Response — Practical Guide",
    date: "2023-02-28",
    type: "technical_guideline",
    series: "CNCS",
    summary: "Guia pratico para a criacao e operacao de um processo de resposta a incidentes de ciberseguranca. Inclui fases de preparacao, detecao, contencao, erradicacao, recuperacao e licoes aprendidas.",
    full_text: "A resposta eficaz a incidentes de ciberseguranca requer preparacao previa, processos claros e equipas treinadas. Este guia apresenta uma abordagem estruturada.\n\nFases da resposta a incidentes:\n\n1. Preparacao:\n- Desenvolver e testar o Plano de Resposta a Incidentes (PRI)\n- Constituir e treinar a equipa CSIRT/CERT interno\n- Estabelecer procedimentos de comunicacao (interna e externa)\n- Preparar ferramentas e infraestrutura de analise forense\n\n2. Detecao e Analise:\n- Monitorizar alertas do SIEM e EDR\n- Triagem e classificacao do incidente (severidade, tipo)\n- Preservar evidencias digitais (chain of custody)\n- Determinar o ambito e impacto inicial\n\n3. Contencao:\n- Isolamento de sistemas afetados\n- Bloqueio de comunicacoes maliciosas (C2)\n- Desativacao de contas comprometidas\n- Implementacao de medidas temporarias de protecao\n\n4. Erradicacao:\n- Remocao de malware e artefactos maliciosos\n- Identificacao e correcao da causa raiz\n- Patching de vulnerabilidades exploradas\n\n5. Recuperacao:\n- Restauro a partir de backups limpos\n- Validacao da integridade dos sistemas\n- Monitorizacao refor cada apos retorno a producao\n\n6. Licoes Aprendidas:\n- Relatorio post-mortem dentro de 30 dias\n- Atualizacao do PRI com base nas licoes aprendidas\n- Partilha de indicadores de compromisso (IoC) com CNCS/CERT.PT",
    topics: JSON.stringify(["resposta incidentes", "CSIRT", "forense digital", "recuperacao", "plano incidentes"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status);
  }
});
insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "CNCS-2024-001",
    title: "Vulnerabilidade Critica em Dispositivos Fortinet FortiGate — CVE-2024-21762",
    date: "2024-02-09",
    severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS 7.4.0-7.4.2", "Fortinet FortiOS 7.2.0-7.2.6", "Fortinet FortiProxy"]),
    summary: "Vulnerabilidade critica de escrita fora dos limites no FortiOS e FortiProxy esta a ser ativamente explorada. Permite execucao remota de codigo sem autenticacao.",
    full_text: "O CNCS alerta para a exploracao ativa da vulnerabilidade CVE-2024-21762 em dispositivos Fortinet FortiGate. A vulnerabilidade e uma escrita fora dos limites (out-of-bounds write) no componente SSL-VPN. CVSS v3.1: 9.6 (Critico).\n\nImpacto: Um atacante nao autenticado pode executar codigo ou comandos arbitrarios atraves de pedidos HTTP especialmente construidos.\n\nVersoes afetadas: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14; FortiProxy 7.4.0-7.4.2.\n\nAcoes recomendadas:\n1. Atualizar para FortiOS 7.4.3, 7.2.7, 7.0.14 ou 6.4.15\n2. Se a atualizacao nao for imediatamente possivel, desativar o acesso HTTPS/HTTP a interface de gestao a partir da internet\n3. Verificar os registos de acesso para indicadores de compromisso\n4. Consultar a lista de IoC publicada pela Fortinet",
    cve_references: JSON.stringify(["CVE-2024-21762"]),
  },
  {
    reference: "CNCS-2023-012",
    title: "Campanha de Phishing Direcionada a Organizacoes Portuguesas — Tecnicas de BEC",
    date: "2023-09-14",
    severity: "high",
    affected_products: JSON.stringify(["Microsoft 365", "Google Workspace", "Plataformas de email corporativo"]),
    summary: "O CNCS identifica campanha de Business Email Compromise (BEC) direcionada a organizacoes portuguesas. Os atacantes comprometem contas de email e redirecionam transferencias bancarias.",
    full_text: "O CNCS identificou uma campanha coordenada de Business Email Compromise (BEC) com impacto em organizacoes portuguesas dos setores financeiro, industrial e de servicos.\n\nDescricao da campanha:\nOs atacantes utilizam tecnicas de spear phishing para comprometer contas de email de executivos ou parceiros comerciais. Apos o compromisso, monitorizam as comunicacoes e intervem em conversas sobre transferencias bancarias, alterando os dados bancarios do destinatario.\n\nTecnicas observadas:\n- Spear phishing com pretextos convincentes (fatura urgente, pedido de transferencia)\n- Utilizacao de dominios lookalike (ex: compania-pt.com vs compania.pt)\n- Regras de email maliciosas para reencaminhar mensagens sem o conhecimento da vitima\n- Comprometimento de contas de fornecedores para aumentar credibilidade\n\nMedidas preventivas:\n1. Ativar MFA em todas as contas de email\n2. Configurar DMARC, DKIM e SPF no dominio\n3. Verificar sempre por telefone (numero conhecido) transferencias bancarias acima de um limiar\n4. Treinar colaboradores para reconhecer sinais de BEC\n5. Monitorizar regras de email e reencaminhamentos suspeitos",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "CNCS-2023-008",
    title: "Vulnerabilidade Critica MOVEit Transfer — Exploracao Massiva CVE-2023-34362",
    date: "2023-06-05",
    severity: "critical",
    affected_products: JSON.stringify(["Progress MOVEit Transfer", "Progress MOVEit Cloud"]),
    summary: "Vulnerabilidade critica de SQL injection no MOVEit Transfer esta a ser explorada em escala global pelo grupo Cl0p. Organizacoes portuguesas podem estar entre os afetados.",
    full_text: "O CNCS alerta para a exploracao em larga escala da vulnerabilidade CVE-2023-34362 no Progress MOVEit Transfer. A vulnerabilidade e uma SQL injection no componente web que permite acesso nao autenticado a dados.\n\nAtribuicao: O grupo de ransomware Cl0p foi identificado como responsavel pela campanha de exploracao massiva.\n\nImpacto potencial: Roubo de ficheiros transferidos atraves do MOVEit, que podem incluir dados pessoais (relevante para notificacao RGPD) e informacao sensivel de negocios.\n\nAcoes imediatas:\n1. Aplicar o patch de seguranca do Progress imediatamente\n2. Bloquear acesso externo ao MOVEit Transfer ate patching\n3. Verificar registos de acesso para SQL injection (procurar por 'machine_id' nas queries)\n4. Avaliar se dados pessoais foram expostos (obrigacao de notificacao CNPD em 72h)\n5. Contactar o CNCS/CERT.PT para suporte na resposta ao incidente",
    cve_references: JSON.stringify(["CVE-2023-34362"]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references);
  }
});
insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
