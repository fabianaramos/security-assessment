class CreateAvaliacoes < ActiveRecord::Migration[8.1]
  def change
    create_table :avaliacoes do |t|
      t.string :organizacao, null: false
      t.string :dominio
      t.integer :participantes
      t.text :observacoes
      t.json :respostas, null: false, default: {}
      t.json :verificacoes, null: false, default: []
      t.json :resultado, null: false, default: {}
      t.integer :nota_geral

      t.timestamps
    end
    add_index :avaliacoes, [ :organizacao, :created_at ]
  end
end
