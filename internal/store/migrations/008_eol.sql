-- endoflife.date lifecycle cycles (Task 29). Dates are YYYY-MM-DD; eol_date is NULL when the feed has no date.
CREATE TABLE eol (product TEXT NOT NULL, cycle TEXT NOT NULL, codename TEXT NOT NULL DEFAULT '', release_date TEXT,
  eol_date TEXT, is_eol INTEGER NOT NULL, latest TEXT NOT NULL DEFAULT '', latest_date TEXT, PRIMARY KEY (product, cycle));
