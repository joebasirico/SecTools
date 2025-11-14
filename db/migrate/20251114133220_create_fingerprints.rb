class CreateFingerprints < ActiveRecord::Migration[8.0]
  def change
    create_table :fingerprints do |t|
      t.string :fingerprint_hash
      t.datetime :first_seen_at
      t.datetime :last_seen_at
      t.integer :visit_count
      t.text :user_agent
      t.string :ip_address

      t.timestamps
    end
    add_index :fingerprints, :fingerprint_hash, unique: true
  end
end
