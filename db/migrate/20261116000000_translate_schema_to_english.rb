# Renames the table and columns from Portuguese to English and translates the
# identifiers stored in the JSON columns (question ids, answers, check keys and
# statuses). User-facing text inside the checks stays in Portuguese.
class TranslateSchemaToEnglish < ActiveRecord::Migration[8.1]
  QUESTION_IDS = {
    "q_2fa_anuncios" => "q_2fa_ads", "q_2fa_email" => "q_2fa_email", "q_2fa_hospedagem" => "q_2fa_hosting",
    "q_gerenciador" => "q_password_manager", "q_senhas_chat" => "q_no_shared_passwords",
    "q_senhas_unicas" => "q_unique_passwords", "q_inventario" => "q_access_inventory",
    "q_minimo_privilegio" => "q_least_privilege", "q_offboarding" => "q_offboarding",
    "q_contas_pessoais" => "q_business_accounts", "q_treinamento" => "q_training",
    "q_canal_suspeita" => "q_report_channel", "q_atualizacoes" => "q_auto_updates",
    "q_bloqueio_tela" => "q_screen_lock", "q_wifi" => "q_wifi", "q_vpn" => "q_vpn",
    "q_cms_atualizado" => "q_cms_updates", "q_plugins_revisados" => "q_unused_plugins",
    "q_backup_sites" => "q_site_backups", "q_backup_arquivos" => "q_file_backups",
    "q_backup_testado" => "q_backup_tested", "q_plano_incidente" => "q_incident_plan"
  }.freeze
  ANSWERS = { "sim" => "yes", "parcial" => "partial", "nao" => "no", "nao_sei" => "unknown" }.freeze
  STATUSES = { "ok" => "pass", "atencao" => "warn", "falha" => "fail", "info" => "info", "erro" => "error" }.freeze
  CHECK_KEYS = { "grupo" => "group", "titulo" => "title", "detalhe" => "detail",
                 "recomendacao" => "recommendation", "peso" => "weight" }.freeze
  CHECK_IDS = { "versao_servidor" => "server_version", "wp_versao" => "wp_version", "cert_confiavel" => "cert_trusted",
                "cert_validade" => "cert_expiry", "tls_versao" => "tls_version" }.freeze

  class MigrationAssessment < ActiveRecord::Base
    self.table_name = "assessments"
  end

  def up
    rename_table :avaliacoes, :assessments
    rename_column :assessments, :organizacao, :organization
    rename_column :assessments, :dominio, :domain
    rename_column :assessments, :participantes, :participants
    rename_column :assessments, :observacoes, :notes
    rename_column :assessments, :respostas, :answers
    rename_column :assessments, :verificacoes, :checks
    rename_column :assessments, :resultado, :result
    rename_column :assessments, :nota_geral, :overall_score

    MigrationAssessment.reset_column_information
    MigrationAssessment.find_each do |row|
      answers = row.answers.to_h { |id, value| [ QUESTION_IDS.fetch(id, id), ANSWERS.fetch(value, value) ] }
      checks = row.checks.map do |check|
        check.to_h { |key, value| [ CHECK_KEYS.fetch(key, key), value ] }
             .merge("id" => CHECK_IDS.fetch(check["id"], check["id"]), "status" => STATUSES.fetch(check["status"], check["status"]))
      end
      result = Scoring.calculate(answers, checks)
      row.update_columns(answers: answers, checks: checks, result: result, overall_score: result["overall"])
    end
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
