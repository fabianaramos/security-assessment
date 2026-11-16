# Self-assessment survey.
#
# Based on the checklist handed out at the 2026.1 workshop (passwords, 2FA,
# phishing, access, backups) and adapted to the routine of a marketing agency
# that manages ad accounts, hosting and client websites.
#
# Each question has a weight from 1 to 3 (3 = highest impact when not done) and
# a recommendation that goes into the action plan when the answer is not "yes".
# User-facing text stays in Portuguese.
module Survey
  ANSWER_VALUES = {
    "yes" => 1.0,
    "partial" => 0.5,
    "no" => 0.0,
    "unknown" => 0.0 # no evidence counts as not done, but is reported separately
  }.freeze

  OPTIONS = [
    [ "yes", "Sim" ],
    [ "partial", "Em parte" ],
    [ "no", "Não" ],
    [ "unknown", "Não sei" ]
  ].freeze

  CATEGORIES = {
    "accounts" => "Contas e senhas",
    "access" => "Gestão de acessos",
    "people" => "Phishing e conscientização",
    "devices" => "Dispositivos e rede",
    "websites" => "Sites e hospedagem",
    "continuity" => "Backup e incidentes"
  }.freeze

  Question = Data.define(:id, :category, :weight, :text, :recommendation)

  QUESTIONS = [
    # Accounts and passwords
    Question.new("q_2fa_ads", "accounts", 3,
      "A verificação em duas etapas (2FA) está ativa em todas as contas de anúncio (Google Ads, Meta Business)?",
      "Ativar 2FA em todas as contas com acesso ao Google Ads e ao Meta Business Suite, de preferência com aplicativo autenticador em vez de SMS."),
    Question.new("q_2fa_email", "accounts", 3,
      "Os e-mails corporativos da equipe têm 2FA ativado?",
      "Ativar 2FA em todos os e-mails corporativos. O e-mail é a chave de recuperação de quase todas as outras contas."),
    Question.new("q_2fa_hosting", "accounts", 3,
      "Os painéis de hospedagem, de registro de domínio e de administração dos sites têm 2FA?",
      "Ativar 2FA na hospedagem, no registro de domínio (ex.: Registro.br) e no painel dos sites (ex.: plugin de 2FA no WordPress)."),
    Question.new("q_password_manager", "accounts", 3,
      "A equipe usa um gerenciador de senhas (ex.: Bitwarden) para guardar e compartilhar acessos?",
      "Criar uma organização no Bitwarden e mover os acessos compartilhados para coleções separadas por cliente."),
    Question.new("q_no_shared_passwords", "accounts", 2,
      "Senhas deixaram de ser enviadas por WhatsApp, e-mail ou planilha?",
      "Proibir o envio de senhas por chat, e-mail ou planilha. Compartilhar apenas pelo gerenciador de senhas e trocar as senhas que já circularam."),
    Question.new("q_unique_passwords", "accounts", 2,
      "Cada conta usa uma senha única e forte (12 caracteres ou mais)?",
      "Usar o gerador do gerenciador de senhas para criar senhas únicas de 12 ou mais caracteres e trocar as senhas repetidas."),
    # Access management
    Question.new("q_access_inventory", "access", 2,
      "Existe uma lista atualizada de quem tem acesso a quais contas (da agência e dos clientes)?",
      "Montar um inventário de acessos por cliente (conta de anúncio, hospedagem, domínio, painel do site) com quem acessa e o nível de permissão."),
    Question.new("q_least_privilege", "access", 2,
      "Cada pessoa tem só o nível de acesso necessário (nem todos são administradores)?",
      "Revisar as permissões e deixar como administrador apenas quem precisa. Usar papéis como 'Anunciante' ou 'Analista' para o restante da equipe."),
    Question.new("q_offboarding", "access", 3,
      "Quando alguém sai da equipe, os acessos são removidos no mesmo dia?",
      "Criar um checklist de desligamento: remover das contas de anúncio, da hospedagem e do gerenciador de senhas e trocar as senhas compartilhadas no mesmo dia."),
    Question.new("q_business_accounts", "access", 2,
      "As contas de anúncio dos clientes ficam vinculadas ao Business Manager ou MCC da empresa, e não a perfis pessoais?",
      "Vincular os ativos dos clientes ao Business Manager/MCC da agência, com pelo menos dois administradores, para não depender do perfil pessoal de ninguém."),
    # Phishing and awareness
    Question.new("q_training", "people", 1,
      "A equipe passou por algum treinamento de segurança nos últimos 6 meses?",
      "Repetir um treinamento curto sobre phishing e golpes a cada 6 meses e incluí-lo na integração de novos colaboradores."),
    Question.new("q_report_channel", "people", 1,
      "Existe uma pessoa ou canal definido para avisar sobre e-mails ou mensagens suspeitas?",
      "Definir um responsável e um canal (ex.: um grupo específico) para reportar mensagens suspeitas antes de clicar ou responder."),
    # Devices and network
    Question.new("q_auto_updates", "devices", 2,
      "Computadores e celulares de trabalho recebem atualizações automáticas do sistema e do navegador?",
      "Ativar as atualizações automáticas do sistema operacional e do navegador em todos os dispositivos de trabalho."),
    Question.new("q_screen_lock", "devices", 2,
      "Os dispositivos têm bloqueio de tela e disco criptografado (FileVault/BitLocker)?",
      "Exigir bloqueio automático de tela e ativar a criptografia do disco (FileVault no Mac, BitLocker no Windows)."),
    Question.new("q_wifi", "devices", 1,
      "O Wi-Fi do escritório tem senha forte e uma rede separada para visitantes?",
      "Usar WPA2/WPA3 com senha forte, trocar a senha padrão do roteador e criar uma rede separada para visitantes."),
    Question.new("q_vpn", "devices", 1,
      "Em redes públicas (cafés, eventos), a equipe usa VPN ou o hotspot do celular?",
      "Orientar o uso de VPN (ex.: plano gratuito do ProtonVPN) ou do hotspot do celular ao trabalhar fora do escritório."),
    # Websites and hosting
    Question.new("q_cms_updates", "websites", 2,
      "Os sites (CMS, temas e plugins) são atualizados pelo menos uma vez por mês?",
      "Criar uma rotina mensal de atualização de CMS, temas e plugins, com backup antes de cada atualização."),
    Question.new("q_unused_plugins", "websites", 1,
      "Plugins e temas sem uso ou abandonados são removidos dos sites?",
      "Remover plugins e temas desativados ou sem atualização há mais de um ano."),
    # Backups and incidents
    Question.new("q_site_backups", "continuity", 3,
      "Os sites têm backup automático guardado fora do servidor de hospedagem?",
      "Configurar backup automático dos sites com cópia fora do servidor (ex.: Google Drive ou outro provedor)."),
    Question.new("q_file_backups", "continuity", 2,
      "Os arquivos da agência (criativos, contratos, planilhas) têm backup?",
      "Manter os arquivos da agência em nuvem com histórico de versões e uma segunda cópia periódica."),
    Question.new("q_backup_tested", "continuity", 1,
      "Algum backup já foi restaurado em teste para confirmar que funciona?",
      "Testar a restauração de um backup pelo menos a cada 3 meses."),
    Question.new("q_incident_plan", "continuity", 2,
      "Existe um passo a passo para quando uma conta (de anúncio, e-mail ou rede social) for invadida?",
      "Escrever um roteiro de resposta a incidentes: quem avisar, como recuperar cada tipo de conta e os links de suporte de Meta e Google.")
  ].freeze

  def self.by_category
    QUESTIONS.group_by(&:category)
  end

  def self.ids
    QUESTIONS.map(&:id)
  end
end
