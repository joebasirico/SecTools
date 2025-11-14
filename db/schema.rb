# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2025_11_14_133220) do
  create_table "fingerprints", force: :cascade do |t|
    t.string "fingerprint_hash"
    t.datetime "first_seen_at"
    t.datetime "last_seen_at"
    t.integer "visit_count"
    t.text "user_agent"
    t.string "ip_address"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["fingerprint_hash"], name: "index_fingerprints_on_fingerprint_hash", unique: true
  end

  create_table "tools", force: :cascade do |t|
    t.string "name"
    t.text "description"
    t.string "category"
    t.boolean "enabled"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end
end
