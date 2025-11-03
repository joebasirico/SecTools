class CreateTools < ActiveRecord::Migration[8.0]
  def change
    create_table :tools do |t|
      t.string :name
      t.text :description
      t.string :category
      t.boolean :enabled

      t.timestamps
    end
  end
end
