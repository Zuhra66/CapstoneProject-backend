// routes/calendar.js
const express = require("express");
const { google } = require("googleapis");
const { pool } = require("../db");

const router = express.Router();

// ----------------- CONFIG -----------------
const TIMEZONE = "America/Los_Angeles";

// OAuth2 client using env variables
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

// Use the long-lived refresh token so Google can always issue access tokens
oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
});

const calendar = google.calendar({ version: "v3", auth: oauth2Client });

// Booking template: adjust as you like (24h "HH:MM" format in provider time)
const BOOKING_TIMES = ["08:00", "09:00", "10:00", "11:00", "13:00", "14:00", "15:00", "16:00"];

// ----------------- GET AVAILABLE TIMES -----------------
router.get("/availability", async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: "Date is required" });

    // Interpret the day's bounds as provider-local time (-08:00)
    const timeMin = new Date(`${date}T00:00:00-08:00`).toISOString();
    const timeMax = new Date(`${date}T23:59:59-08:00`).toISOString();

    const eventsResponse = await calendar.events.list({
      calendarId: "primary",
      timeMin,
      timeMax,
      singleEvents: true,
      orderBy: "startTime",
    });

    const events = eventsResponse.data.items || [];

    const busyTimes = events.map((e) => {
      const start = new Date(e.start.dateTime || e.start.date);
      const end = new Date(e.end.dateTime || e.end.date);
      return { start, end };
    });

    const freeSlots = BOOKING_TIMES.filter((slot) => {
      const [hour, minute] = slot.split(":");

      // Build provider-local time using fixed -08:00 offset
      const start = new Date(`${date}T${hour}:${minute}:00-08:00`);
      const end = new Date(start.getTime() + 60 * 60 * 1000);

      // If this slot overlaps ANY busy event, it's not free
      return !busyTimes.some(
          (busy) => start < busy.end && end > busy.start
      );
    });

    // Format times for display in provider timezone (PST)
    const formatted = freeSlots.map((slot) => {
      const [hour, minute] = slot.split(":");
      const d = new Date(`${date}T${hour}:${minute}:00-08:00`);
      return d.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        timeZone: TIMEZONE,
      });
    });

    res.json({ times: formatted, totalEvents: events.length });
  } catch (err) {
    console.error("Fetching availability failed:", err);
    res.status(500).json({ error: "Failed to fetch availability", details: err.message });
  }
});

// ----------------- HELPER -----------------
function convertTo24Hour(time12h) {
  const [time, modifier] = time12h.split(" ");
  let [hours, minutes] = time.split(":");

  if (modifier === "PM" && hours !== "12") {
    hours = String(parseInt(hours) + 12);
  }
  if (modifier === "AM" && hours === "12") {
    hours = "00";
  }

  return `${hours}:${minutes}`;
}

// ----------------- BOOK APPOINTMENT -----------------
router.post("/book", async (req, res) => {
  try {
    const {
      date,
      time,
      email,
      userId,
      appointment_type,
      service_id,
      provider_id,
      location_id,
      notes
    } = req.body;

    if (!date || !time || !email) {
      return res.status(400).json({ success: false, error: "Missing fields" });
    }

    const time24 = convertTo24Hour(time);

    // Build provider-local RFC3339 timestamps with explicit -08:00 offset
    const [hStr, mStr] = time24.split(":");
    const hourNum = parseInt(hStr, 10);
    const nextHour = String(hourNum + 1).padStart(2, "0");

    const startLocal = `${date}T${time24}:00-08:00`;
    const endLocal = `${date}T${nextHour}:${mStr}:00-08:00`;

    // Store as Date objects in DB
    const startDateTime = new Date(startLocal);
    const endDateTime = new Date(endLocal);

    // Insert using appointment_date field
    const dbRes = await pool.query(
        `INSERT INTO appointments (
         user_id,
         email,
         appointment_type,
         appointment_date,
         start_time,
         end_time,
         service_id,
         provider_id,
         location_id,
         notes,
         status
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'scheduled')
       RETURNING *`,
        [
          userId || null,
          email,
          appointment_type || null,
          date,
          startDateTime,
          endDateTime,
          service_id || null,
          provider_id || null,
          location_id || null,
          notes || null,
        ]
    );

    const appointment = dbRes.rows[0];

    // ---------------- GOOGLE CALENDAR EVENT ----------------
    const event = {
      summary: appointment.appointment_type || "Appointment",
      description: `Booked by: ${email}`,
      attendees: [
        { email },
        { email: "empowermeddev@gmail.com" },
      ],
      start: {
        dateTime: startLocal,
      },
      end: {
        dateTime: endLocal,
      },
      reminders: {
        useDefault: true,
      },
    };

    const created = await calendar.events.insert({
      calendarId: "primary",
      sendUpdates: "all",
      requestBody: event,
    });

    await pool.query(
        `UPDATE appointments
       SET google_event_id=$1, updated_at = NOW()
       WHERE id=$2`,
        [created.data.id, appointment.id]
    );

    return res.json({
      success: true,
      appointment,
      googleEvent: created.data,
    });
  } catch (error) {
    console.error("Booking error:", error);
    return res.status(500).json({ success: false, error: error.message || "Booking failed" });
  }
});

// ----------------- USER APPOINTMENTS (JWT-AWARE + FILTERED) -----------------
const checkJwt = require("../middleware/auth0-check");

router.get("/user-appointments", checkJwt, async (req, res) => {
  try {
    const authUser = req.auth;
    if (!authUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const auth0Id = authUser.sub;
    if (!auth0Id) {
      return res.status(401).json({ error: "Invalid token (no sub)" });
    }

    // Find user in DB
    const userResult = await pool.query(
        `SELECT id FROM users WHERE auth0_id = $1 LIMIT 1`,
        [auth0Id]
    );

    if (userResult.rows.length === 0) {
      return res.json({ appointments: [] });
    }

    const userId = userResult.rows[0].id;

    // Fetch **non-canceled** appointments
    const dbRes = await pool.query(
        `
      SELECT
        id,
        appointment_type,
        appointment_date AS date,
        start_time,
        end_time,
        email,
        status,
        service_id,
        provider_id,
        location_id,
        notes,
        google_event_id
        FROM appointments
        WHERE user_id = $1
        ORDER BY appointment_date, start_time
      `,
        [userId]
    );

    return res.json({ appointments: dbRes.rows });

  } catch (err) {
    console.error("Fetch user appointments error:", err);
    res.status(500).json({
      error: "Failed to fetch user appointments",
      details: err.message,
    });
  }
});

// ----------------- CANCEL APPOINTMENT -----------------
router.post("/cancel", async (req, res) => {
  try {
    const { appointmentId } = req.body;

    if (!appointmentId)
      return res.status(400).json({ error: "appointmentId is required" });

    // Get the Google event ID
    const result = await pool.query(
        `SELECT google_event_id FROM appointments WHERE id=$1`,
        [appointmentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Appointment not found" });
    }

    const googleEventId = result.rows[0].google_event_id;

    // Delete Google Calendar event if exists
    if (googleEventId) {
      try {
        await calendar.events.delete({
          calendarId: "primary",
          eventId: googleEventId,
          sendUpdates: "all",
        });
      } catch (e) {
        // Silent fail for Google event deletion
      }
    }

    // Update the DB record to canceled
    await pool.query(
        `UPDATE appointments
       SET status='canceled', updated_at=NOW()
       WHERE id=$1`,
        [appointmentId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Cancel appointment error:", err);
    res.status(500).json({ error: "Failed to cancel appointment" });
  }
});

// ---------------------------------------------------
// ADMIN: GET ALL APPOINTMENTS (DB + GOOGLE CALENDAR)
// ---------------------------------------------------
router.get("/admin-appointments", async (req, res) => {
  try {
    // Fetch DB appointments
    const dbRes = await pool.query(`
      SELECT
        id,
        appointment_type,
        appointment_date AS date,
        start_time,
        end_time,
        email,
        status,
        google_event_id
      FROM appointments
      ORDER BY appointment_date, start_time
    `);

    const dbAppointments = dbRes.rows;

    // Create a map for DB Google event IDs
    const dbByGoogleId = new Map();
    for (const appt of dbAppointments) {
      if (appt.google_event_id) {
        dbByGoogleId.set(appt.google_event_id, appt);
      }
    }

    // Fetch upcoming Google Calendar events
    const now = new Date();
    const oneYearAhead = new Date();
    oneYearAhead.setFullYear(now.getFullYear() + 1);

    const googleRes = await calendar.events.list({
      calendarId: "primary",
      timeMin: now.toISOString(),
      timeMax: oneYearAhead.toISOString(),
      singleEvents: true,
      orderBy: "startTime"
    });

    const googleEvents = googleRes.data.items || [];

    // Normalize Google events (with email fallback)
    const googleAppointments = googleEvents.map(event => {
      const start = new Date(event.start.dateTime || event.start.date);
      const end = new Date(event.end.dateTime || event.end.date);

      // Fallback priority for finding email
      const attendeeEmail = event.attendees?.[0]?.email || null;
      const creatorEmail = event.creator?.email || null;
      const organizerEmail = event.organizer?.email || null;

      const finalEmail =
          attendeeEmail ||
          creatorEmail ||
          organizerEmail ||
          null;

      return {
        id: event.id,
        email: finalEmail,
        appointment_type: event.summary || "Google Event",
        date: start.toISOString().split("T")[0],
        start_time: start,
        end_time: end,
        status: null,
        google_event_id: event.id
      };
    });

    // Combine DB + Google-only
    const finalList = [...dbAppointments];

    googleAppointments.forEach(gEvent => {
      if (!dbByGoogleId.has(gEvent.id)) {
        finalList.push(gEvent);
      }
    });

    res.json({ appointments: finalList });
  } catch (err) {
    console.error("Admin appointments error:", err);
    res.status(500).json({ error: "Failed to fetch admin appointments" });
  }
});

// ----------------- ADMIN CANCEL APPOINTMENT -----------------
router.post("/admin-cancel", async (req, res) => {
  try {
    const { appointmentId } = req.body;

    if (!appointmentId)
      return res.status(400).json({ error: "appointmentId is required" });

    // Get the Google event ID
    const result = await pool.query(
        `SELECT google_event_id FROM appointments WHERE id=$1`,
        [appointmentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Appointment not found" });
    }

    const googleEventId = result.rows[0].google_event_id;

    // Delete Google Calendar event if exists
    if (googleEventId) {
      try {
        await calendar.events.delete({
          calendarId: "primary",
          eventId: googleEventId,
          sendUpdates: "all",
        });
      } catch (e) {
        // Silent fail for Google event deletion
      }
    }

    // Update DB record
    await pool.query(
        `UPDATE appointments
       SET status='canceled', updated_at=NOW()
       WHERE id=$1`,
        [appointmentId]
    );

    return res.json({ success: true });

  } catch (err) {
    console.error("Admin cancel error:", err);
    res.status(500).json({ error: "Failed to cancel appointment" });
  }
});

// ----------------- ADMIN RESCHEDULE -----------------
router.post("/admin-reschedule", async (req, res) => {
  try {
    const { appointmentId, newDate, newTime } = req.body;

    if (!appointmentId || !newDate || !newTime)
      return res.status(400).json({ error: "Missing fields" });

    const convertTo24Hour = (t) => {
      const [time, mod] = t.split(" ");
      let [h, m] = time.split(":");
      if (mod === "PM" && h !== "12") h = String(Number(h) + 12);
      if (mod === "AM" && h === "12") h = "00";
      return `${h}:${m}`;
    };

    const time24 = convertTo24Hour(newTime);

    const result = await pool.query(
        `SELECT google_event_id FROM appointments WHERE id=$1`,
        [appointmentId]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "Appointment not found" });

    const googleEventId = result.rows[0].google_event_id;

    // Build provider-local strings with explicit -08:00 offset
    const [hStr, mStr] = time24.split(":");
    const hourNum = parseInt(hStr, 10);
    const nextHour = String(hourNum + 1).padStart(2, "0");

    const startLocal = `${newDate}T${time24}:00-08:00`;
    const endLocal = `${newDate}T${nextHour}:${mStr}:00-08:00`;

    // GOOGLE EVENT UPDATE
    if (googleEventId) {
      await calendar.events.patch({
        calendarId: "primary",
        eventId: googleEventId,
        sendUpdates: "all",
        requestBody: {
          start: { dateTime: startLocal },
          end:   { dateTime: endLocal },
        },
      });
    }

    // Update DB with real Date objects
    const start = new Date(startLocal);
    const end = new Date(endLocal);

    await pool.query(
        `UPDATE appointments
       SET appointment_date=$1, start_time=$2, end_time=$3
       WHERE id=$4`,
        [newDate, start, end, appointmentId]
    );

    res.json({ success: true });

  } catch (err) {
    console.error("Admin reschedule error:", err);
    res.status(500).json({ error: "Admin reschedule failed" });
  }
});

// ----------------- DEBUG TIMEZONE ENDPOINT -----------------
router.get("/debug", (req, res) => {
  try {
    const { date = "2025-02-05", time = "08:00" } = req.query;

    const localString = `${date}T${time}:00-08:00`;
    const asDate = new Date(localString);

    res.json({
      input: { date, time },
      constructed_string: localString,
      js_date_toString: asDate.toString(),
      js_date_toISOString: asDate.toISOString(),
      js_date_getHours: asDate.getHours(),
      js_date_getUTC_Hours: asDate.getUTCHours(),
      server_timezone_offset_minutes: asDate.getTimezoneOffset(),
      now: {
        toString: new Date().toString(),
        toISOString: new Date().toISOString(),
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;