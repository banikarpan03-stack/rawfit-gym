const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const DATABASE_URL = process.env.DATABASE_URL;
const isPostgres = !!DATABASE_URL;

let _pgPool = null;

function getDb() {
  if (isPostgres) {
    if (!_pgPool) {
      const { Pool } = require("pg");
      _pgPool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, connectionTimeoutMillis: 10000, idleTimeoutMillis: 30000 });
    }
    return { pool: _pgPool, query: (text, params) => _pgPool.query(text, params) };
  }
  const Database = require("better-sqlite3");
  const path = require("path");
  const fs = require("fs");
  const DB_PATH = path.join(__dirname, "..", "data", "gym.db");
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  return db;
}

async function initDatabase() {
  if (isPostgres) {
    const { pool } = getDb();
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        uniqueCode TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'MEMBER',
        dob TEXT,
        address TEXT,
        photo TEXT,
        height REAL,
        weight REAL,
        medicalIssues TEXT,
        startDate TEXT,
        endDate TEXT,
        discount REAL DEFAULT 0,
        extraDays INTEGER DEFAULT 0,
        totalAmount REAL,
        packageId TEXT,
        createdAt TEXT DEFAULT (NOW()),
        updatedAt TEXT DEFAULT (NOW()),
        FOREIGN KEY (packageId) REFERENCES packages(id)
      );

      CREATE TABLE IF NOT EXISTS packages (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        duration INTEGER NOT NULL,
        price REAL NOT NULL,
        description TEXT,
        isActive INTEGER DEFAULT 1,
        createdAt TEXT DEFAULT (NOW())
      );

      CREATE TABLE IF NOT EXISTS attendance (
        id TEXT PRIMARY KEY,
        memberId TEXT NOT NULL,
        checkIn TEXT DEFAULT (NOW()),
        checkOut TEXT,
        isManual INTEGER DEFAULT 0,
        markedBy TEXT,
        createdAt TEXT DEFAULT (NOW()),
        FOREIGN KEY (memberId) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS exercises (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT,
        videoUrl TEXT,
        gifUrl TEXT,
        difficulty TEXT DEFAULT 'beginner',
        muscleGroup TEXT,
        createdAt TEXT DEFAULT (NOW())
      );

      CREATE TABLE IF NOT EXISTS diet_templates (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        targetCalories INTEGER,
        meals TEXT,
        description TEXT,
        createdAt TEXT DEFAULT (NOW())
      );

      CREATE TABLE IF NOT EXISTS workout_templates (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        exercises TEXT,
        difficulty TEXT,
        description TEXT,
        createdAt TEXT DEFAULT (NOW())
      );

      CREATE TABLE IF NOT EXISTS member_charts (
        id TEXT PRIMARY KEY,
        memberId TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT NOT NULL,
        startDate TEXT,
        endDate TEXT,
        history TEXT DEFAULT '[]',
        createdAt TEXT DEFAULT (NOW()),
        updatedAt TEXT DEFAULT (NOW()),
        FOREIGN KEY (memberId) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        memberId TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT,
        isRead INTEGER DEFAULT 0,
        createdAt TEXT DEFAULT (NOW()),
        FOREIGN KEY (memberId) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        memberId TEXT NOT NULL,
        amount REAL NOT NULL,
        method TEXT,
        notes TEXT,
        date TEXT DEFAULT (NOW()),
        FOREIGN KEY (memberId) REFERENCES users(id)
      );
    `);
    return pool;
  }

  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      uniqueCode TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'MEMBER',
      dob TEXT,
      address TEXT,
      photo TEXT,
      height REAL,
      weight REAL,
      medicalIssues TEXT,
      startDate TEXT,
      endDate TEXT,
      discount REAL DEFAULT 0,
      extraDays INTEGER DEFAULT 0,
      totalAmount REAL,
      packageId TEXT,
      createdAt TEXT DEFAULT (datetime('now')),
      updatedAt TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (packageId) REFERENCES packages(id)
    );

    CREATE TABLE IF NOT EXISTS packages (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      duration INTEGER NOT NULL,
      price REAL NOT NULL,
      description TEXT,
      isActive INTEGER DEFAULT 1,
      createdAt TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id TEXT PRIMARY KEY,
      memberId TEXT NOT NULL,
      checkIn TEXT DEFAULT (datetime('now')),
      checkOut TEXT,
      isManual INTEGER DEFAULT 0,
      markedBy TEXT,
      createdAt TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (memberId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS exercises (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT,
      videoUrl TEXT,
      difficulty TEXT DEFAULT 'beginner',
      muscleGroup TEXT,
      createdAt TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS diet_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      targetCalories INTEGER,
      meals TEXT,
      description TEXT,
      createdAt TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS workout_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      exercises TEXT,
      difficulty TEXT,
      description TEXT,
      createdAt TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS member_charts (
      id TEXT PRIMARY KEY,
      memberId TEXT NOT NULL,
      type TEXT NOT NULL,
      content TEXT NOT NULL,
      startDate TEXT,
      endDate TEXT,
      history TEXT DEFAULT '[]',
      createdAt TEXT DEFAULT (datetime('now')),
      updatedAt TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (memberId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      memberId TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT,
      isRead INTEGER DEFAULT 0,
      createdAt TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (memberId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      memberId TEXT NOT NULL,
      amount REAL NOT NULL,
      method TEXT,
      notes TEXT,
      date TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (memberId) REFERENCES users(id)
    );
  `);
  return db;
}

async function seedDatabase(db) {
  if (isPostgres) {
    const { pool } = db;
    const adminExists = (await pool.query("SELECT id FROM users WHERE phone = $1", ["9999999999"])).rows[0];
    if (!adminExists) {
      const adminPw = bcrypt.hashSync("admin", 10);
      await pool.query("INSERT INTO users (id, uniqueCode, name, phone, password, role) VALUES ($1,$2,$3,$4,$5,$6)", [uuidv4(), "RM-2024-ADMIN", "Admin", "9999999999", adminPw, "ADMIN"]);
    }
    const pkgCount = (await pool.query("SELECT COUNT(*) as c FROM packages")).rows[0].c;
    if (pkgCount === 0) {
      const pkgs = [
        ["basic-monthly", "Basic Monthly", 30, 500, "Access to gym equipment for 30 days"],
        ["premium-monthly", "Premium Monthly", 30, 800, "Access to gym + classes for 30 days"],
        ["quarterly", "Quarterly", 90, 1400, "3 months premium membership"],
        ["half-yearly", "Half Yearly", 180, 2500, "6 months premium membership"],
        ["annual", "Annual", 365, 4500, "1 year premium membership"],
      ];
      for (const p of pkgs) await pool.query("INSERT INTO packages (id, name, duration, price, description) VALUES ($1,$2,$3,$4,$5)", p);
    }
    console.log("Exercise seeding deferred to first request");
        const dtCount = (await pool.query("SELECT COUNT(*) as c FROM diet_templates")).rows[0].c;
    if (dtCount === 0) {
      const templates = [
        ["Weight Loss Plan", 1500, JSON.stringify([{ time: "7:00 AM", name: "Oatmeal with fruits", calories: 300, items: ["Oats", "Banana", "Honey", "Milk"] }, { time: "10:00 AM", name: "Mid-morning snack", calories: 150, items: ["Apple", "Almonds"] }, { time: "1:00 PM", name: "Lunch", calories: 450, items: ["Brown rice", "Grilled chicken", "Salad", "Dal"] }, { time: "4:00 PM", name: "Pre-workout", calories: 150, items: ["Banana", "Protein shake"] }, { time: "7:00 PM", name: "Dinner", calories: 350, items: ["Roti", "Vegetables", "Paneer"] }, { time: "9:00 PM", name: "Before bed", calories: 100, items: ["Warm milk", "Turmeric"] }]), "Low calorie diet for weight loss"],
        ["Muscle Gain Plan", 2500, JSON.stringify([{ time: "6:00 AM", name: "Early breakfast", calories: 400, items: ["Eggs (4)", "Whole wheat toast", "Banana"] }, { time: "9:00 AM", name: "Post-workout", calories: 400, items: ["Protein shake", "Oats", "Peanut butter"] }, { time: "12:00 PM", name: "Lunch", calories: 600, items: ["Rice", "Chicken breast", "Vegetables", "Dal"] }, { time: "3:00 PM", name: "Snack", calories: 300, items: ["Greek yogurt", "Mixed nuts", "Fruits"] }, { time: "6:00 PM", name: "Pre-workout", calories: 200, items: ["Banana", "Black coffee"] }, { time: "8:00 PM", name: "Dinner", calories: 500, items: ["Roti", "Fish/Paneer", "Vegetables", "Salad"] }, { time: "10:00 PM", name: "Before bed", calories: 100, items: ["Casein protein", "Milk"] }]), "High protein diet for muscle building"],
        ["Maintenance Plan", 2000, JSON.stringify([{ time: "7:00 AM", name: "Breakfast", calories: 400, items: ["Poha/Upma", "Eggs", "Fruits"] }, { time: "10:00 AM", name: "Snack", calories: 200, items: ["Nuts", "Green tea"] }, { time: "1:00 PM", name: "Lunch", calories: 500, items: ["Rice", "Dal", "Vegetables", "Curd"] }, { time: "4:00 PM", name: "Evening snack", calories: 200, items: ["Sprouts", "Fruits"] }, { time: "7:00 PM", name: "Dinner", calories: 500, items: ["Roti", "Paneer/Chicken", "Salad"] }, { time: "9:00 PM", name: "Before bed", calories: 200, items: ["Milk", "Dry fruits"] }]), "Balanced diet for maintaining weight"],
      ];
      for (const t of templates) await pool.query("INSERT INTO diet_templates (id, name, targetCalories, meals, description) VALUES ($1,$2,$3,$4,$5)", [uuidv4(), ...t]);
    }
    const wtCount = (await pool.query("SELECT COUNT(*) as c FROM workout_templates")).rows[0].c;
    if (wtCount === 0) {
      const templates = [
        ["Beginner Full Body", "beginner", "Full body workout for beginners", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Push-ups", sets: 3, reps: 10, rest: "60s" }, { name: "Squats", sets: 3, reps: 12, rest: "60s" }, { name: "Bent Over Row", sets: 3, reps: 10, rest: "60s" }, { name: "Plank", sets: 3, duration: "30s", rest: "45s" }, { name: "Bicep Curls", sets: 3, reps: 12, rest: "45s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
        ["Chest & Triceps", "intermediate", "Upper body push workout", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Bench Press", sets: 4, reps: 8, rest: "90s" }, { name: "Incline Bench Press", sets: 3, reps: 10, rest: "90s" }, { name: "Dumbbell Fly", sets: 3, reps: 12, rest: "60s" }, { name: "Tricep Dips", sets: 3, reps: 10, rest: "60s" }, { name: "Tricep Pushdown", sets: 3, reps: 12, rest: "60s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
        ["Back & Biceps", "intermediate", "Upper body pull workout", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Deadlift", sets: 4, reps: 6, rest: "120s" }, { name: "Pull-ups", sets: 3, reps: 8, rest: "90s" }, { name: "Bent Over Row", sets: 3, reps: 10, rest: "90s" }, { name: "Lat Pulldown", sets: 3, reps: 12, rest: "60s" }, { name: "Bicep Curls", sets: 3, reps: 12, rest: "60s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
        ["Leg Day", "intermediate", "Lower body workout", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Squats", sets: 4, reps: 10, rest: "120s" }, { name: "Leg Press", sets: 3, reps: 12, rest: "90s" }, { name: "Lunges", sets: 3, reps: 12, rest: "60s" }, { name: "Calf Raises", sets: 4, reps: 15, rest: "45s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
        ["HIIT Cardio", "advanced", "High intensity interval training", JSON.stringify([{ name: "Jumping Jacks", duration: "30s", rest: "15s", type: "cardio" }, { name: "Burpees", duration: "30s", rest: "15s", type: "cardio" }, { name: "Mountain Climbers", duration: "30s", rest: "15s", type: "cardio" }, { name: "High Knees", duration: "30s", rest: "15s", type: "cardio" }, { name: "Squat Jumps", duration: "30s", rest: "15s", type: "cardio" }, { name: "Plank", duration: "30s", rest: "15s", type: "core" }, { name: "Repeat 3 rounds", type: "note" }])],
      ];
      for (const t of templates) await pool.query("INSERT INTO workout_templates (id, name, difficulty, exercises, description) VALUES ($1,$2,$3,$4,$5)", [uuidv4(), ...t]);
    }
    console.log("PostgreSQL seeded!");
    return;
  }

  const sqliteDb = getDb();
  const adminExists = sqliteDb.prepare("SELECT id FROM users WHERE phone = ?").get("9999999999");
  if (!adminExists) {
    const adminPw = bcrypt.hashSync("admin", 10);
    sqliteDb.prepare("INSERT INTO users (id, uniqueCode, name, phone, password, role) VALUES (?, ?, ?, ?, ?, ?)").run(uuidv4(), "RM-2024-ADMIN", "Admin", "9999999999", adminPw, "ADMIN");
  }

  const pkgCount = sqliteDb.prepare("SELECT COUNT(*) as c FROM packages").get().c;
  if (pkgCount === 0) {
    const pkgs = [
      ["basic-monthly", "Basic Monthly", 30, 500, "Access to gym equipment for 30 days"],
      ["premium-monthly", "Premium Monthly", 30, 800, "Access to gym + classes for 30 days"],
      ["quarterly", "Quarterly", 90, 1400, "3 months premium membership"],
      ["half-yearly", "Half Yearly", 180, 2500, "6 months premium membership"],
      ["annual", "Annual", 365, 4500, "1 year premium membership"],
    ];
    const stmt = sqliteDb.prepare("INSERT INTO packages (id, name, duration, price, description) VALUES (?, ?, ?, ?, ?)");
    for (const p of pkgs) stmt.run(...p);
  }

  const exCount = sqliteDb.prepare("SELECT COUNT(*) as c FROM exercises").get().c;
  if (exCount === 0) {
    const exercises = [
      ["Bench Press", "chest", "Lie on bench, lower bar to chest, push up", "intermediate", "chest"],
      ["Push-ups", "chest", "Standard push-up position, lower body to ground", "beginner", "chest"],
      ["Dumbbell Fly", "chest", "Lie on bench, extend arms with dumbbells, lower in arc", "intermediate", "chest"],
      ["Incline Bench Press", "chest", "Bench press on inclined bench", "intermediate", "upper chest"],
      ["Pull-ups", "back", "Hang from bar, pull body up", "intermediate", "lats"],
      ["Deadlift", "back", "Lift barbell from ground to hip level", "advanced", "lower back"],
      ["Bent Over Row", "back", "Bend forward, pull barbell to abdomen", "intermediate", "middle back"],
      ["Lat Pulldown", "back", "Pull bar down to chest on cable machine", "beginner", "lats"],
      ["Squats", "legs", "Lower body as if sitting, stand back up", "intermediate", "quadriceps"],
      ["Leg Press", "legs", "Push weight away with legs on machine", "beginner", "quadriceps"],
      ["Lunges", "legs", "Step forward, lower body, return", "beginner", "quadriceps"],
      ["Calf Raises", "legs", "Rise up on toes, lower back down", "beginner", "calves"],
      ["Bicep Curls", "arms", "Curl dumbbell up to shoulder", "beginner", "biceps"],
      ["Tricep Dips", "arms", "Dip body down on parallel bars", "intermediate", "triceps"],
      ["Hammer Curls", "arms", "Curl with neutral grip", "beginner", "biceps"],
      ["Tricep Pushdown", "arms", "Push cable down with straight bar", "beginner", "triceps"],
      ["Overhead Press", "shoulders", "Press barbell overhead from shoulders", "intermediate", "shoulders"],
      ["Lateral Raises", "shoulders", "Raise dumbbells to sides", "beginner", "side delts"],
      ["Front Raises", "shoulders", "Raise dumbbells to front", "beginner", "front delts"],
      ["Plank", "core", "Hold push-up position on elbows", "beginner", "abs"],
      ["Crunches", "core", "Lie on back, curl shoulders up", "beginner", "abs"],
      ["Leg Raises", "core", "Lie on back, raise legs up", "intermediate", "lower abs"],
      ["Russian Twists", "core", "Sit, twist torso side to side", "intermediate", "obliques"],
    ];
    const stmt = sqliteDb.prepare("INSERT INTO exercises (id, name, category, description, difficulty, muscleGroup) VALUES (?, ?, ?, ?, ?, ?)");
    for (const e of exercises) stmt.run(uuidv4(), ...e);
  }

  const dtCount = sqliteDb.prepare("SELECT COUNT(*) as c FROM diet_templates").get().c;
  if (dtCount === 0) {
    const templates = [
      ["Weight Loss Plan", 1500, "Low calorie diet for weight loss", JSON.stringify([{ time: "7:00 AM", name: "Oatmeal with fruits", calories: 300, items: ["Oats", "Banana", "Honey", "Milk"] }, { time: "10:00 AM", name: "Mid-morning snack", calories: 150, items: ["Apple", "Almonds"] }, { time: "1:00 PM", name: "Lunch", calories: 450, items: ["Brown rice", "Grilled chicken", "Salad", "Dal"] }, { time: "4:00 PM", name: "Pre-workout", calories: 150, items: ["Banana", "Protein shake"] }, { time: "7:00 PM", name: "Dinner", calories: 350, items: ["Roti", "Vegetables", "Paneer"] }, { time: "9:00 PM", name: "Before bed", calories: 100, items: ["Warm milk", "Turmeric"] }])],
      ["Muscle Gain Plan", 2500, "High protein diet for muscle building", JSON.stringify([{ time: "6:00 AM", name: "Early breakfast", calories: 400, items: ["Eggs (4)", "Whole wheat toast", "Banana"] }, { time: "9:00 AM", name: "Post-workout", calories: 400, items: ["Protein shake", "Oats", "Peanut butter"] }, { time: "12:00 PM", name: "Lunch", calories: 600, items: ["Rice", "Chicken breast", "Vegetables", "Dal"] }, { time: "3:00 PM", name: "Snack", calories: 300, items: ["Greek yogurt", "Mixed nuts", "Fruits"] }, { time: "6:00 PM", name: "Pre-workout", calories: 200, items: ["Banana", "Black coffee"] }, { time: "8:00 PM", name: "Dinner", calories: 500, items: ["Roti", "Fish/Paneer", "Vegetables", "Salad"] }, { time: "10:00 PM", name: "Before bed", calories: 100, items: ["Casein protein", "Milk"] }])],
      ["Maintenance Plan", 2000, "Balanced diet for maintaining weight", JSON.stringify([{ time: "7:00 AM", name: "Breakfast", calories: 400, items: ["Poha/Upma", "Eggs", "Fruits"] }, { time: "10:00 AM", name: "Snack", calories: 200, items: ["Nuts", "Green tea"] }, { time: "1:00 PM", name: "Lunch", calories: 500, items: ["Rice", "Dal", "Vegetables", "Curd"] }, { time: "4:00 PM", name: "Evening snack", calories: 200, items: ["Sprouts", "Fruits"] }, { time: "7:00 PM", name: "Dinner", calories: 500, items: ["Roti", "Paneer/Chicken", "Salad"] }, { time: "9:00 PM", name: "Before bed", calories: 200, items: ["Milk", "Dry fruits"] }])],
    ];
    const stmt = sqliteDb.prepare("INSERT INTO diet_templates (id, name, targetCalories, meals, description) VALUES (?, ?, ?, ?, ?)");
    for (const t of templates) stmt.run(uuidv4(), ...t);
  }

  const wtCount = sqliteDb.prepare("SELECT COUNT(*) as c FROM workout_templates").get().c;
  if (wtCount === 0) {
    const templates = [
      ["Beginner Full Body", "beginner", "Full body workout for beginners", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Push-ups", sets: 3, reps: 10, rest: "60s" }, { name: "Squats", sets: 3, reps: 12, rest: "60s" }, { name: "Bent Over Row", sets: 3, reps: 10, rest: "60s" }, { name: "Plank", sets: 3, duration: "30s", rest: "45s" }, { name: "Bicep Curls", sets: 3, reps: 12, rest: "45s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
      ["Chest & Triceps", "intermediate", "Upper body push workout", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Bench Press", sets: 4, reps: 8, rest: "90s" }, { name: "Incline Bench Press", sets: 3, reps: 10, rest: "90s" }, { name: "Dumbbell Fly", sets: 3, reps: 12, rest: "60s" }, { name: "Tricep Dips", sets: 3, reps: 10, rest: "60s" }, { name: "Tricep Pushdown", sets: 3, reps: 12, rest: "60s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
      ["Back & Biceps", "intermediate", "Upper body pull workout", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Deadlift", sets: 4, reps: 6, rest: "120s" }, { name: "Pull-ups", sets: 3, reps: 8, rest: "90s" }, { name: "Bent Over Row", sets: 3, reps: 10, rest: "90s" }, { name: "Lat Pulldown", sets: 3, reps: 12, rest: "60s" }, { name: "Bicep Curls", sets: 3, reps: 12, rest: "60s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
      ["Leg Day", "intermediate", "Lower body workout", JSON.stringify([{ name: "Warm-up", duration: "5 min", type: "cardio" }, { name: "Squats", sets: 4, reps: 10, rest: "120s" }, { name: "Leg Press", sets: 3, reps: 12, rest: "90s" }, { name: "Lunges", sets: 3, reps: 12, rest: "60s" }, { name: "Calf Raises", sets: 4, reps: 15, rest: "45s" }, { name: "Cool down", duration: "5 min", type: "stretching" }])],
      ["HIIT Cardio", "advanced", "High intensity interval training", JSON.stringify([{ name: "Jumping Jacks", duration: "30s", rest: "15s", type: "cardio" }, { name: "Burpees", duration: "30s", rest: "15s", type: "cardio" }, { name: "Mountain Climbers", duration: "30s", rest: "15s", type: "cardio" }, { name: "High Knees", duration: "30s", rest: "15s", type: "cardio" }, { name: "Squat Jumps", duration: "30s", rest: "15s", type: "cardio" }, { name: "Plank", duration: "30s", rest: "15s", type: "core" }, { name: "Repeat 3 rounds", type: "note" }])],
    ];
    const stmt = sqliteDb.prepare("INSERT INTO workout_templates (id, name, difficulty, exercises, description) VALUES (?, ?, ?, ?, ?)");
    for (const t of templates) stmt.run(uuidv4(), ...t);
  }

  console.log("SQLite seeded!");
}

module.exports = { getDb, initDatabase, seedDatabase, isPostgres };
