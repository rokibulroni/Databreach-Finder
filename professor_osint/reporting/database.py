import os
import json
import sqlite3
import logging

from ..common import console
from ..constants import POSINT_CONFIG_DIR


class DatabaseMixin:
    """SQLite persistence and JSON/config loading."""

    def load_json(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Could not load {filepath}: {e}")
            return {}

    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    logging.info(f"Loaded config from {config_path}")
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading config.json: {e}")
                console.print(f"[bold red][!] Error loading config.json: {e}[/bold red]")
        return {}

    def get_network_config(self):
        config_path = os.path.join(POSINT_CONFIG_DIR, "network.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"mode": "direct", "proxy_url": "", "wireguard_conf": ""}

    def save_network_config(self, mode, proxy_url="", wireguard_conf=""):
        config_path = os.path.join(POSINT_CONFIG_DIR, "network.json")
        data = {
            "mode": mode,
            "proxy_url": proxy_url,
            "wireguard_conf": wireguard_conf
        }
        try:
            with open(config_path, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save network config: {e}")

    def init_db(self):
        try:
            self.conn = sqlite3.connect('professor_osint.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT,
                    url TEXT,
                    extracted_data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(query, url, extracted_data)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS social_footprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    platform TEXT,
                    url TEXT,
                    bio TEXT,
                    image_url TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(username, platform)
                )
            ''')
            try:
                self.cursor.execute('ALTER TABLE social_footprints ADD COLUMN bio TEXT')
                self.cursor.execute('ALTER TABLE social_footprints ADD COLUMN image_url TEXT')
                self.cursor.execute('ALTER TABLE social_footprints ADD COLUMN confidence TEXT')
            except:
                pass
                
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS live_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT,
                    source TEXT,
                    headline TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(query, source, headline)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_infrastructure (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    ip_address TEXT,
                    location TEXT,
                    isp TEXT,
                    server_tech TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, ip_address)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS social_xray (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform TEXT,
                    url TEXT,
                    entry_type TEXT,
                    author_hash TEXT,
                    posted_at TEXT,
                    content TEXT,
                    engagement TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(url, entry_type, author_hash, content)
                )
            ''')
            self.conn.commit()
            logging.info("Database initialized successfully.")
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")

    def is_duplicate(self, url, data):
        self.cursor.execute('SELECT 1 FROM findings WHERE query = ? AND url = ? AND extracted_data = ?', (self.query, url, data))
        return self.cursor.fetchone() is not None

    def save_to_db(self, url, data):
        try:
            self.cursor.execute('INSERT INTO findings (query, url, extracted_data) VALUES (?, ?, ?)', (self.query, url, data))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False 
        except Exception as e:
            logging.error(f"Error saving to DB: {e}")
            return False

    def save_social_to_db(self, username, platform, url, bio=None, image_url=None, confidence="100%"):
        try:
            # Check if columns exist first, handle dynamically if possible, or just catch error
            self.cursor.execute('INSERT INTO social_footprints (username, platform, url, bio, image_url, confidence) VALUES (?, ?, ?, ?, ?, ?)', (username, platform, url, bio, image_url, confidence))
            self.conn.commit()
        except sqlite3.OperationalError:
            try:
                self.cursor.execute('INSERT INTO social_footprints (username, platform, url, bio, image_url) VALUES (?, ?, ?, ?, ?)', (username, platform, url, bio, image_url))
                self.conn.commit()
            except sqlite3.IntegrityError:
                if bio or image_url:
                    self.cursor.execute('UPDATE social_footprints SET bio = ?, image_url = ? WHERE username = ? AND platform = ?', (bio, image_url, username, platform))
                    self.conn.commit()
        except sqlite3.IntegrityError:
            if bio or image_url:
                self.cursor.execute('UPDATE social_footprints SET bio = ?, image_url = ?, confidence = ? WHERE username = ? AND platform = ?', (bio, image_url, confidence, username, platform))
                self.conn.commit()
        except Exception as e:
            logging.error(f"Error saving social DB: {e}")

    def save_social_xray_to_db(self, platform, url, entry_type, author_hash, posted_at, content, engagement):
        """Persist one extracted post/comment. Author is stored anonymized (hashed)."""
        try:
            self.cursor.execute(
                'INSERT INTO social_xray (platform, url, entry_type, author_hash, posted_at, content, engagement) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (platform, url, entry_type, author_hash, posted_at, content, engagement)
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass
        except Exception as e:
            logging.error(f"Error saving social x-ray DB: {e}")

    def save_news_to_db(self, query, source, headline):
        try:
            self.cursor.execute('INSERT INTO live_intelligence (query, source, headline) VALUES (?, ?, ?)', (query, source, headline))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass 
        except Exception as e:
            logging.error(f"Error saving news DB: {e}")

    def save_webcheck_to_db(self, domain, ip, location, isp, server_tech):
        try:
            self.cursor.execute('INSERT INTO web_infrastructure (domain, ip_address, location, isp, server_tech) VALUES (?, ?, ?, ?, ?)', (domain, ip, location, isp, server_tech))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass 
        except Exception as e:
            logging.error(f"Error saving webcheck DB: {e}")
