class LocalStorageBridge {
  static setObject(key, value) {
    try {
      const jsonString = JSON.stringify(value);
      localStorage.setItem(key, jsonString);
      return true;
    } catch (error) {
      return false;
    }
  }

  static getObject(key, defaultValue = null) {
    try {
      const jsonString = localStorage.getItem(key);
      if (jsonString === null) {
        return defaultValue;
      }

      const parsed = JSON.parse(jsonString);
      return parsed;
    } catch (error) {
      return defaultValue;
    }
  }

  static setPrimitive(key, value) {
    try {
      localStorage.setItem(key, String(value));
      return true;
    } catch (error) {
      return false;
    }
  }

  static getPrimitive(key, defaultValue = null) {
    try {
      const value = localStorage.getItem(key);
      if (value === null) {
        return defaultValue;
      }

      return value;
    } catch (error) {
      return defaultValue;
    }
  }

  static remove(key) {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (error) {
      return false;
    }
  }

  static hasKey(key) {
    try {
      const exists = localStorage.getItem(key) !== null;
      return exists;
    } catch (error) {
      return false;
    }
  }

  static clear() {
    try {
      localStorage.clear();
      return true;
    } catch (error) {
      return false;
    }
  }

  static getAllKeys() {
    try {
      const keys = Object.keys(localStorage);
      return keys;
    } catch (error) {
      return [];
    }
  }

  static debug(key = null) {
    if (key) {
      const value = localStorage.getItem(key);
      console.log({
        raw: value,
        type: typeof value,
        parsed: (() => {
          try {
            return JSON.parse(value);
          } catch {
            return "Not valid JSON";
          }
        })(),
      });
    } else {
      console.log({
        keys: Object.keys(localStorage),
        contents: Object.fromEntries(
          Object.keys(localStorage).map((k) => [k, localStorage.getItem(k)])
        ),
      });
    }
  }

  static migrateData(key) {
    try {
      const value = localStorage.getItem(key);
      if (!value) return false;

      let parsed;
      try {
        parsed = JSON.parse(value);
      } catch {
        return false;
      }

      if (typeof parsed === "string") {
        try {
          const doubleParsed = JSON.parse(parsed);
          localStorage.setItem(key, JSON.stringify(doubleParsed));
          return true;
        } catch {
          return false;
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }
}

window.LocalStorageBridge = LocalStorageBridge;

if (typeof module !== "undefined" && module.exports) {
  module.exports = LocalStorageBridge;
}
