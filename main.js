const utils = require('@iobroker/adapter-core'); // Importiere die ioBroker Adapter-Bibliothek
const axios = require('axios'); // Importiere axios für HTTP-Anfragen
const qs = require('qs'); // Importiere qs für URL-Encoded Daten
const crypto = require('crypto'); // Importiere crypto für kryptografische Funktionen
const forge = require('node-forge'); // Importiere node-forge für PKI
const { DateTime } = require('luxon'); // Importiere luxon für Datums- und Zeitfunktionen
const awsIot = require('aws-iot-device-sdk'); // Importiere AWS IoT SDK

class LgThinq extends utils.Adapter {
    constructor(options) {
        super({
            ...options,
            name: 'lg-thinq',
        });
        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload', this.onUnload.bind(this));
        
        // Initialisiere benötigte Variablen
        this.session = null;
        this._homes = null;
        this.modelInfos = {};
        this.coursetypes = {};
        this.deviceControls = {};
        this.deviceJson = {};
        this.mqttdata = {};
        this.mqttC = null;
        this.isRestart = false;
        this.targetKeys = {};
    }

    /**
     * Wird aufgerufen, wenn der Adapter bereit ist.
     */
    async onReady() {
        this.log.debug("Adapter wird gestartet...");
        try {
            // Initialisiere die Sitzung durch Login
            this.session = await this.login(this.config.user, this.config.password);
            if (!this.session || !this.session.access_token) {
                this.log.error("Login fehlgeschlagen. Adapter kann nicht gestartet werden.");
                await this.setStateAsync("info.connection", false, true);
                return;
            }
            this.log.info("Login erfolgreich. Sitzung initialisiert.");
            
            // Weitere Initialisierungslogik
            await this.initializeAdapter();
        } catch (error) {
            this.log.error(`Fehler beim Starten des Adapters: ${error.message}`);
            await this.setStateAsync("info.connection", false, true);
        }
    }

    /**
     * Initialisiere den Adapter nach erfolgreichem Login.
     */
    async initializeAdapter() {
        try {
            // Homes abrufen
            const homes = await this.getListHomes();
            if (!homes) {
                this.log.error("Keine Homes gefunden. Adapter wird beendet.");
                await this.setStateAsync("info.connection", false, true);
                return;
            }
            this.log.info(`Gefundene Homes: ${homes.length}`);
            
            // Geräte initialisieren
            await this.initializeDevices(homes);
            
            // Starte Überwachungsprozesse
            this.startPollMonitor();
            this.startMqtt();
        } catch (error) {
            this.log.error(`Fehler bei der Adapter-Initialisierung: ${error.message}`);
            await this.setStateAsync("info.connection", false, true);
        }
    }

    /**
     * Login-Funktion mit verbesserter Fehlerbehandlung und Logging.
     */
    async login(username, password) {
        this.log.debug(`Versuche, Benutzer ${username} anzumelden.`);
        
        const data = {
            username: username,
            password: this.hashPassword(password), // Stelle sicher, dass die Passwort-Hash-Funktion korrekt funktioniert
        };

        const headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        };

        const loginUrl = `${this.gateway.empTermsUri}/emp/v2.0/account/session/${encodeURIComponent(username)}`;
        this.log.debug(`Login URL: ${loginUrl}`);
        this.log.debug(`Login Daten: ${qs.stringify(data)}`);
        this.log.debug(`Login Headers: ${JSON.stringify(headers)}`);

        try {
            const res = await this.requestClient.post(loginUrl, qs.stringify(data), { headers });
            this.log.debug(`Login Antwort: ${JSON.stringify(res.data)}`);
            
            if (res.data && res.data.account) {
                // Fortfahren mit dem Token-Handling
                const secretKey = await this.getSecretKey();
                const timestamp = DateTime.utc().toRFC2822();
                const empData = {
                    account_type: res.data.account.userIDType,
                    client_id: constants.CLIENT_ID,
                    country_code: res.data.account.country,
                    username: res.data.account.userID,
                };
                const empUrl = `/emp/oauth2/token/empsession${qs.stringify(empData, { addQueryPrefix: true })}`;
                const signature = this.signature(`${empUrl}\n${timestamp}`, secretKey);
                const empHeaders = {
                    "lgemp-x-app-key": constants.OAUTH_CLIENT_KEY,
                    "lgemp-x-date": timestamp,
                    "lgemp-x-session-key": res.data.account.loginSessionID,
                    "lgemp-x-signature": signature,
                    Accept: "application/json",
                    "X-Device-Type": "M01",
                    "X-Device-Platform": "ADR",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Access-Control-Allow-Origin": "*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                };
                this.log.debug(`Emp Headers: ${JSON.stringify(empHeaders)}`);
                const tokenResponse = await this.requestClient.post("https://emp-oauth.lgecloud.com/emp/oauth2/token/empsession", qs.stringify(empData), { headers: empHeaders });
                this.log.debug(`Token Antwort: ${JSON.stringify(tokenResponse.data)}`);
                
                if (tokenResponse.data && tokenResponse.data.access_token) {
                    this.session = tokenResponse.data;
                    this.lgeapi_url = tokenResponse.data.oauth2_backend_url || this.lgeapi_url;
                    await this.setStateAsync("info.connection", true, true);
                    this.log.info("Login erfolgreich und Sitzung initialisiert.");
                    return this.session;
                } else {
                    this.log.error("Login fehlgeschlagen: Kein Zugriffstoken erhalten.");
                    return null;
                }
            } else {
                this.log.error("Login fehlgeschlagen: Ungültige Antwortstruktur.");
                return null;
            }
        } catch (err) {
            if (!err.response) {
                this.log.error(`Login Fehler: ${err.message}`);
            } else {
                this.log.error(`Login Fehler: ${JSON.stringify(err.response.data)}`);
                const { code, message } = err.response.data.error || {};
                if (code === "MS.001.03") {
                    this.log.error(`Konfigurationsfehler: Überprüfe das Land in der Konfiguration - ${message}`);
                }
            }
            return null;
        }
    }

    /**
     * Refresh Token-Funktion mit verbesserter Fehlerbehandlung und Logging.
     */
    async refreshNewToken() {
        this.log.debug("Versuche, das Zugriffstoken zu aktualisieren.");
        const tokenUrl = `${this.lgeapi_url}oauth/1.0/oauth2/token`;

        if (!this.session || !this.session.refresh_token) {
            this.log.warn("Missing Session Infos! Sitzung ist nicht initialisiert.");
            this.handleSessionMissing();
            return;
        }

        const data = {
            grant_type: "refresh_token",
            refresh_token: this.session.refresh_token,
        };

        const timestamp = DateTime.utc().toRFC2822();
        const requestUrl = `/oauth/1.0/oauth2/token${qs.stringify(data, { addQueryPrefix: true })}`;
        const signature = this.signature(`${requestUrl}\n${timestamp}`, constants.OAUTH_SECRET_KEY);

        const headers = {
            "x-lge-app-os": "ADR",
            "x-lge-appkey": constants.CLIENT_ID,
            "x-lge-oauth-signature": signature,
            "x-lge-oauth-date": timestamp,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        };

        this.log.debug(`Refresh Token URL: ${tokenUrl}`);
        this.log.debug(`Refresh Token Daten: ${qs.stringify(data)}`);
        this.log.debug(`Refresh Token Headers: ${JSON.stringify(headers)}`);

        try {
            const resp = await this.requestClient.post(tokenUrl, qs.stringify(data), { headers });
            this.log.debug(`Refresh Token Antwort: ${JSON.stringify(resp.data)}`);

            if (resp.data && resp.data.access_token) {
                this.session.access_token = resp.data.access_token;
                await this.updateSessionDetails();
                await this.setStateAsync("info.connection", true, true);
                this.log.info("Token erfolgreich aktualisiert.");
            } else {
                this.log.warn("Refresh Token fehlgeschlagen: Kein Zugriffstoken erhalten.");
                await this.handleRefreshTokenFailure();
            }
        } catch (error) {
            this.log.error(`Refresh Token Fehler: ${error.message}`);
            if (error.response) {
                this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
            }
            await this.handleRefreshTokenFailure();
        }
    }

    /**
     * Behandelt fehlgeschlagenes Token-Refresh.
     */
    async handleRefreshTokenFailure() {
        this.log.warn("Versuche erneut zu melden aufgrund fehlgeschlagenen Token-Refresh.");
        this.session = await this.login(this.config.user, this.config.password).catch((error) => {
            this.log.error(`Login nach Refresh Token Fehler: ${error.message}`);
        });
    }

    /**
     * Behandelt fehlende Session-Informationen.
     */
    handleSessionMissing() {
        this.log.warn("Session fehlt. Versuche erneut zu starten oder neu anzumelden.");
        // Hier kannst du weitere Maßnahmen hinzufügen, z.B. Neustart des Adapters
    }

    /**
     * Holt die Liste der Homes für den aktuellen Benutzer.
     * @returns {Promise<Array|null>} Eine Liste von Homes oder null bei Fehlern.
     */
    async getListHomes() {
        if (!this._homes) {
            const headers = this.defaultHeaders;
            const homesUrl = `${this.gateway.thinq2Uri}/service/homes`;
            this.log.debug(`Abrufen der Homes von URL: ${homesUrl}`);
            try {
                const res = await this.requestClient.get(homesUrl, { headers });
                if (res.data) {
                    this._homes = res.data;
                    this.log.debug(`Gefundene Homes: ${JSON.stringify(this._homes)}`);
                } else {
                    this.log.warn("Keine Daten von der Homes API erhalten.");
                    this._homes = null;
                }
            } catch (error) {
                this.log.error(`Fehler beim Abrufen der Homes: ${error.message}`);
                if (error.response) {
                    this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
                }
                // Zusätzliche Maßnahmen je nach Fehlerart
                if (error.response && error.response.status === 401) {
                    this.log.warn("Authentifizierungsfehler beim Abrufen der Homes. Versuche, das Token zu aktualisieren.");
                    await this.refreshNewToken();
                }
                this._homes = null;
            }
        }

        return this._homes;
    }

    /**
     * Initialisiert die Geräte basierend auf den Homes.
     * @param {Array} homes - Die Liste der Homes.
     */
    async initializeDevices(homes) {
        try {
            const devices = await this.getDevicesAsync();
            if (!devices || devices.length === 0) {
                this.log.warn("Keine Geräte gefunden.");
                return;
            }

            for (const device of devices) {
                await this.getDeviceModelInfo(device);
                await this.extractValues(device);
            }
        } catch (error) {
            this.log.error(`Fehler bei der Geräte-Initialisierung: ${error.message}`);
        }
    }

    /**
     * Holt die Geräteinformationen und initialisiert sie.
     * @returns {Promise<Array>} Eine Liste von Geräten.
     */
    async getDevicesAsync() {
        // Deine bestehende getDevicesAsync-Funktion mit verbessertem Logging
        // ...
    }

    /**
     * Holt die Modellinformationen für ein Gerät.
     * @param {Object} device - Das Gerät.
     * @returns {Promise<Object|string>} Das Gerätemodell oder "NOK" bei Fehlern.
     */
    async getDeviceModelInfo(device) {
        let uris = {};
        const modelJsonPath = `${this.adapterDir}/lib/modelJsonUri`;

        try {
            if (fs.existsSync(modelJsonPath)) {
                const data_uris = fs.readFileSync(modelJsonPath, "utf-8");
                uris = JSON.parse(data_uris);
                this.log.debug(`Geladene URIs: ${JSON.stringify(uris)}`);
            } else {
                uris.data = {};
                this.log.warn(`ModelJsonUri-Datei nicht gefunden. Erstelle leeres URIs-Objekt.`);
            }
        } catch (err) {
            this.log.error(`Fehler beim Lesen der ModelJsonUri-Datei: ${err.message}`);
            uris.data = {};
        }

        if (!device.modelJsonUri) {
            this.log.error(`Missing Modelinfo for device - ${device.deviceId}. Bitte erstelle ein neues Issue auf GitHub!`);
            return "NOK";
        }

        this.log.debug(`Get Device Model Info for device: ${device.deviceId}`);
        let stopp = false;
        let deviceModel = await this.requestClient
            .get(device.modelJsonUri)
            .then((res) => res.data)
            .catch((error) => {
                this.log.error(`Fehler beim Abrufen des Device Models für ${device.deviceId}: ${error.message}`);
                return null;
            });

        if (!deviceModel) {
            if (uris.data[device.modelJsonUri]) {
                this.log.info(`Use local modelJsonUri for device ${device.deviceId}`);
                deviceModel = uris.data[device.modelJsonUri];
            }
        }

        if (deviceModel) {
            if (!uris.data[device.modelJsonUri]) {
                uris.data[device.modelJsonUri] = deviceModel;
                fs.writeFile(modelJsonPath, JSON.stringify(uris), (err) => {
                    if (err) {
                        this.log.error(`Fehler beim Schreiben der ModelJsonUri-Datei: ${err.message}`);
                    } else {
                        this.log.info(`ModelJsonUri-Datei erfolgreich aktualisiert.`);
                    }
                });
            }

            // Erstelle oder aktualisiere die Remote-Steuerelemente
            await this.setObjectNotExistsAsync(`${device.deviceId}.remote`, {
                type: "channel",
                common: {
                    name: "remote control device",
                    desc: "Create by LG-Thinq Adapter",
                },
                native: {},
            });

            this.coursetypes[device.deviceId] = {};
            if (deviceModel["Config"]) {
                this.coursetypes[device.deviceId]["smartCourseType"] = deviceModel.Config.smartCourseType || "";
                this.coursetypes[device.deviceId]["courseType"] = deviceModel.Config.courseType || "";
                this.coursetypes[device.deviceId]["downloadedCourseType"] = deviceModel.Config.downloadedCourseType || "courseType";
            }

            // Verarbeitung basierend auf dem Gerätetyp und Plattformtyp
            if (device.deviceType === 406) {
                await this.handleDeviceType406(device, deviceModel, stopp);
            } else if (device.deviceType === 401) {
                await this.handleDeviceType401(device, deviceModel, stopp);
            }

            // Allgemeine Verarbeitung der ControlWifi-Eigenschaften
            if (deviceModel["ControlWifi"]) {
                await this.handleControlWifi(device, deviceModel, stopp);
            }
        } else {
            this.log.error(`Device Model Info konnte nicht abgerufen werden für ${device.deviceId}`);
            return "NOK";
        }

        return deviceModel;
    }

    /**
     * Behandelt spezifische Logik für Gerätetyp 401.
     */
    async handleDeviceType401(device, deviceModel, stopp) {
        this.log.debug(`Verarbeite Gerätetyp 401 für Gerät: ${device.deviceId}`);
        if (deviceModel["ControlWifi"] && deviceModel["ControlWifi"].type) {
            this.log.debug(`DeviceModel.type: ${deviceModel["ControlWifi"].type}`);
        } else {
            this.log.debug("DeviceModel.type nicht gefunden");
        }

        if (device.platformType === "thinq2") {
            await this.createAirRemoteStates(device, deviceModel);
            await this.createStatistic(device.deviceId, 401);
            const dataKeys = deviceModel["ControlDevice"];
            if (deviceModel && dataKeys[0] && dataKeys[0].dataKey) {
                try {
                    const arr_dataKey = dataKeys[0].dataKey.split("|").pop();
                    deviceModel["folder"] = arr_dataKey.split(".")[0];
                } catch (error) {
                    this.log.info("Cannot find the snapshot folder!");
                }
            }
            stopp = true;
        } else if (device.platformType === "thinq1" && deviceModel["ControlWifi"].type === "JSON") {
            this.log.debug("Gerät 401 thinq1 gefunden.");
            await this.createAirRemoteThinq1States(device, deviceModel, constants);
            await this.createStatistic(device.deviceId, 401);
            stopp = true;
        } else {
            this.log.warn(`Gerätetyp 401 mit platformType ${device.platformType} wird noch nicht unterstützt`);
            this.log.info(JSON.stringify(device));
        }
    }

    /**
     * Behandelt spezifische Logik für Gerätetyp 406.
     */
    async handleDeviceType406(device, deviceModel, stopp) {
        this.log.debug(`Verarbeite Gerätetyp 406 für Gerät: ${device.deviceId}`);
        if (deviceModel["ControlWifi"] && deviceModel["ControlWifi"].type) {
            this.log.debug(`DeviceModel.type: ${deviceModel["ControlWifi"].type}`);
        } else {
            this.log.debug("DeviceModel.type nicht gefunden");
        }

        if (device.platformType === "thinq2") {
            await this.createHeatRemoteStates(device, deviceModel);
            await this.createStatistic(device.deviceId, 406);
            const dataKeys = deviceModel["ControlDevice"];
            if (deviceModel && dataKeys[0] && dataKeys[0].dataKey) {
                try {
                    const arr_dataKey = dataKeys[0].dataKey.split("|").pop();
                    deviceModel["folder"] = arr_dataKey.split(".")[0];
                } catch (error) {
                    this.log.info("Cannot find the snapshot folder!");
                }
            }
            stopp = true;
        } else {
            this.log.warn(`Gerätetyp 406 mit platformType ${device.platformType} wird noch nicht unterstützt`);
            this.log.info(JSON.stringify(device));
        }
    }

    /**
     * Behandelt die ControlWifi-Eigenschaften für ein Gerät.
     */
    async handleControlWifi(device, deviceModel, stopp) {
        this.log.debug(`Verarbeite ControlWifi für Gerät: ${device.deviceId}`);
        this.log.debug(JSON.stringify(deviceModel["ControlWifi"]));
        let controlWifi = deviceModel["ControlWifi"];
        try {
            deviceModel["folder"] = "";
            const firstWifiKey = Object.keys(deviceModel["ControlWifi"])[0];
            if (firstWifiKey) {
                const firstDataKey = Object.keys(deviceModel["ControlWifi"][firstWifiKey]?.data || {})[0];
                deviceModel["folder"] = firstDataKey ? firstDataKey.split(".")[0] : "";
            }
        } catch (error) {
            this.log.debug("Cannot find the folder!");
        }

        if (deviceModel["ControlWifi"].action) {
            controlWifi = deviceModel["ControlWifi"].action;
        }

        this.deviceControls[device.deviceId] = controlWifi;
        this.deviceJson[device.deviceId] = deviceModel;

        if (deviceModel["Info"]?.productType === "REF") {
            await this.createFridge(device, deviceModel);
            await this.createStatistic(device.deviceId, 101);
        } else if (stopp) {
            return deviceModel;
        } else {
            if (controlWifi) {
                for (const control in controlWifi) {
                    if (control === "WMDownload" && device.platformType === "thinq2") {
                        await this.createremote(device.deviceId, control, deviceModel);
                    }
                    const common = {
                        name: control,
                        type: "boolean",
                        role: "switch",
                        write: true,
                        read: true,
                        def: false,
                    };
                    if (
                        ["WMDownload", "WMStart", "WMStop", "WMOff", "WMWakeup"].includes(control)
                    ) {
                        common.role = "button";
                        common.def = false;
                    }
                    await this.createDataPoint(`${device.deviceId}.remote.${control}`, common, "state");
                }
            }
        }
    }

    /**
     * Extrahiert Werte aus dem Geräte-Modell und erstellt Datenpunkte.
     * @param {Object} device - Das Gerät.
     */
    async extractValues(device) {
        const deviceModel = this.modelInfos[device.deviceId];
        if (!deviceModel) {
            this.log.warn(`Keine Modellinformationen für Gerät ${device.deviceId}`);
            return;
        }

        let langPack = null;
        let langPath = device.langPackProductTypeUri ? "langPackProductTypeUri" : 
                       device.langPackModelUri ? "langPackModelUri" : null;

        if (langPath) {
            langPack = await this.requestClient.get(device[langPath])
                .then(res => res.data)
                .catch(error => {
                    this.log.info(`Fehler beim Abrufen des Sprachpakets für Gerät ${device.deviceId}: ${error}`);
                    return null;
                });
        }

        if (deviceModel["MonitoringValue"] || deviceModel["Value"]) {
            this.log.debug("Extrahiere Werte aus dem Modell");
            const deviceType = deviceModel["deviceType"] || 0;
            let type = "";

            if (device.snapshot && deviceModel["folder"] && deviceType !== 401) {
                type = deviceModel["folder"];
            }

            let path = `${device.deviceId}.snapshot.`;
            if (type) {
                path += `${type}.`;
            }

            if (deviceType === 202) {
                await this.setDryerBlindStates(path);
            }

            const downloadedCourseType = this.coursetypes[device.deviceId]?.downloadedCourseType || "courseType";
            const smartCourseType = this.coursetypes[device.deviceId]?.smartCourseType || "WASHERANDDRYER";
            const courseType = this.coursetypes[device.deviceId]?.courseType || "WASHERANDDRYER";
            const onlynumber = /^-?[0-9]+$/;

            if (deviceModel["MonitoringValue"]) {
                for (const state in deviceModel["MonitoringValue"]) {
                    const fullPath = `${path}${state}`;
                    this.log.debug(`Verarbeite Datenpunkt: ${fullPath}`);

                    let obj;
                    try {
                        obj = await this.getObjectAsync(fullPath);
                        if (!obj) {
                            this.log.warn(`Datenpunkt ${fullPath} existiert nicht. Überspringen.`);
                            continue;
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Abrufen des Objekts ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const common = { ...obj.common };
                    const commons = {};
                    let valueObject = deviceModel["MonitoringValue"][state]?.option || null;
                    const valueDefault = deviceModel["MonitoringValue"][state]?.default || null;

                    if (deviceModel["MonitoringValue"][state]?.value_mapping) {
                        valueObject = deviceModel["MonitoringValue"][state].value_mapping;
                    }
                    if (deviceModel["MonitoringValue"][state]?.value_validation) {
                        valueObject = deviceModel["MonitoringValue"][state].value_validation;
                    }

                    if (valueObject && typeof valueObject === "object") {
                        if (valueObject.max) {
                            common.min = 0;
                            switch (state) {
                                case "moreLessTime":
                                    common.max = 200;
                                    break;
                                case "timeSetting":
                                    common.max = 360;
                                    break;
                                case "AirPolution":
                                case "airState.quality.odor":
                                    common.max = 2000000;
                                    break;
                                case "airState.miscFuncState.autoDryRemainTime":
                                    common.max = 300;
                                    break;
                                default:
                                    common.max = (valueDefault != null && valueDefault > valueObject.max) ? valueDefault : valueObject.max;
                                    break;
                            }
                            common.def = valueDefault ? parseFloat(valueDefault) : 0;
                        } else {
                            const values = Object.keys(valueObject);
                            for (const value of values) {
                                const content = valueObject[value];
                                if (typeof content === "string") {
                                    const new_content = content.replace("@", "");
                                    if (langPack?.[content]) {
                                        commons[value] = langPack[content].toString("utf-8");
                                    } else if (constants[`${this.lang}Translation`]?.[new_content]) {
                                        commons[value] = constants[`${this.lang}Translation`][new_content];
                                    } else {
                                        commons[value] = new_content;
                                    }
                                }
                            }
                        }
                    }

                    if (Object.keys(commons).length > 0) {
                        common.states = commons;
                    }

                    try {
                        if (!obj) {
                            await this.setObjectNotExistsAsync(fullPath, {
                                type: "state",
                                common: common,
                                native: {},
                            }).catch((error) => {
                                this.log.error(`Fehler beim Erstellen des Datenpunkts ${fullPath}: ${error}`);
                            });
                        } else {
                            obj.common = common;
                            await this.setObjectAsync(fullPath, obj).catch((error) => {
                                this.log.error(`Fehler beim Aktualisieren des Datenpunkts ${fullPath}: ${error}`);
                            });
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Verarbeiten des Datenpunkts ${fullPath}: ${error.message}`);
                    }
                }
            }

            if (deviceModel["Value"]) {
                for (const state in deviceModel["Value"]) {
                    const fullPath = `${path}${state}`;
                    this.log.debug(`Verarbeite Value-Datenpunkt: ${fullPath} (Problem mit 401 device)`);

                    let obj;
                    try {
                        obj = await this.getObjectAsync(fullPath);
                        if (!obj) {
                            this.log.warn(`Value-Datenpunkt ${fullPath} existiert nicht. Überspringen.`);
                            continue;
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Abrufen des Value-Objekts ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const common = { ...obj.common };
                    const commons = {};
                    let valueObject = deviceModel["Value"][state]?.option || null;
                    const valueDefault = deviceModel["Value"][state]?.default || null;

                    if (deviceModel["Value"][state]?.value_mapping) {
                        valueObject = deviceModel["Value"][state].value_mapping;
                    }
                    if (deviceModel["Value"][state]?.value_validation) {
                        valueObject = deviceModel["Value"][state].value_validation;
                    }

                    if (valueObject && typeof valueObject === "object") {
                        if (valueObject.max) {
                            common.min = 0;
                            switch (state) {
                                case "moreLessTime":
                                    common.max = 200;
                                    break;
                                case "timeSetting":
                                    common.max = 360;
                                    break;
                                case "AirPolution":
                                case "airState.quality.odor":
                                    common.max = 2000000;
                                    break;
                                case "airState.miscFuncState.autoDryRemainTime":
                                    common.max = 300;
                                    break;
                                default:
                                    common.max = (valueDefault != null && valueDefault > valueObject.max) ? valueDefault : valueObject.max;
                                    break;
                            }
                            common.def = valueDefault ? parseFloat(valueDefault) : 0;
                        } else {
                            const values = Object.keys(valueObject);
                            for (const value of values) {
                                const content = valueObject[value];
                                if (typeof content === "string") {
                                    const new_content = content.replace("@", "");
                                    if (langPack?.[content]) {
                                        commons[value] = langPack[content].toString("utf-8");
                                    } else if (constants[`${this.lang}Translation`]?.[new_content]) {
                                        commons[value] = constants[`${this.lang}Translation`][new_content];
                                    } else {
                                        commons[value] = new_content;
                                    }
                                }
                            }
                        }
                    }

                    if (Object.keys(commons).length > 0) {
                        common.states = commons;
                    }

                    try {
                        if (!obj) {
                            await this.setObjectNotExistsAsync(fullPath, {
                                type: "state",
                                common: common,
                                native: {},
                            }).catch((error) => {
                                this.log.error(`Fehler beim Erstellen des Value-Datenpunkts ${fullPath}: ${error}`);
                            });
                        } else {
                            obj.common = common;
                            await this.setObjectAsync(fullPath, obj).catch((error) => {
                                this.log.error(`Fehler beim Aktualisieren des Value-Datenpunkts ${fullPath}: ${error}`);
                            });
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Verarbeiten des Value-Datenpunkts ${fullPath}: ${error.message}`);
                    }
                }
            }
        }
    }

    /**
     * Startet den MQTT-Client mit verbesserter Fehlerbehandlung und Logging.
     */
    async start_mqtt() {
        try {
            if (!this.mqttdata.privateKey) {
                const mqttHost = await this.getMqttInfo(constants.MQTT_URL);
                let mqttHostParts = [];
                if (mqttHost && mqttHost.result && mqttHost.result.mqttServer) {
                    if (mqttHost.result.apiServer && !mqttHost.result.apiServer.includes("-ats.iot")) {
                        mqttHostParts = mqttHost.result.mqttServer.split(".iot.");
                        this.mqttdata["apiServer"] = `${mqttHostParts[0]}-ats.iot.${mqttHostParts[1]}`;
                    }
                    if (!mqttHost.result.mqttServer.includes("-ats.iot")) {
                        mqttHostParts = mqttHost.result.mqttServer.split(".iot.");
                        this.mqttdata["mqttServer"] = `${mqttHostParts[0]}-ats.iot.${mqttHostParts[1]}`;
                    }
                } else {
                    this.log.info("Cannot load MQTT Host");
                    return;
                }
                this.log.info("Found MQTT Host");
                this.mqttdata.mqttServer = this.resolveUrl(this.mqttdata.mqttServer, "", true);
                const mqttCer = await this.getMqttInfo(constants.MQTT_CER);
                if (!mqttCer) {
                    this.log.info("Cannot load AWS CER");
                    return;
                }
                this.mqttdata.amazon = mqttCer;
                this.log.info("Found AWS CER");
                const certGenerator = await this.getMqttInfo(constants.MQTT_AZU);
                if (certGenerator.privKey && certGenerator.csr) {
                    this.mqttdata.privateKey = certGenerator.privKey;
                    this.mqttdata.key = certGenerator.csr;
                } else {
                    const key = forge.pki.rsa.generateKeyPair(2048);
                    const keys = {};
                    keys.privateKey = forge.pki.privateKeyToPem(key.privateKey);
                    this.mqttdata.privateKey = keys.privateKey;
                    keys.publicKey = forge.pki.publicKeyToPem(key.publicKey);
                    const csr = forge.pki.createCertificationRequest();
                    csr.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
                    csr.setSubject([
                        {
                            shortName: "CN",
                            value: "AWS IoT Certificate",
                        },
                        {
                            shortName: "O",
                            value: "Amazon",
                        },
                    ]);
                    csr.sign(forge.pki.privateKeyFromPem(keys.privateKey), forge.md.sha256.create());
                    this.mqttdata.key = forge.pki.certificationRequestToPem(csr);
                }
                this.log.info("Create certification done");
            }

            await this.getUser("service/users/client", {});
            const client_certificate = await this.getUser("service/users/client/certificate", {
                csr: this.mqttdata.key,
            });
            if (!client_certificate || !client_certificate.result || !client_certificate.result.certificatePem) {
                this.log.info("Cannot load certificatePem");
                return;
            }
            if (!client_certificate.result.subscriptions) {
                this.log.info("Cannot load subscriptions");
                return;
            }
            this.mqttdata.certificatePem = client_certificate.result.certificatePem;
            this.mqttdata.subscriptions = client_certificate.result.subscriptions;
            if (this.isRestart) {
                this.log.info("Start MQTT Connection");
            }
            this.connectMqtt();
        } catch (error) {
            this.log.error(`Create CSR ERROR: ${error.message}`);
            this.mqttC = null;
            this.isRestart = true;
            if (error.message.indexOf("0110") === -1) {
                this.terms();
            }
        }
    }

    /**
     * Verbindet den MQTT-Client mit verbesserter Fehlerbehandlung und Logging.
     */
    async connectMqtt() {
        try {
            let region = "eu-west-1";
            const split_mqtt = this.mqttdata.mqttServer.split(".");
            if (split_mqtt.length > 1) {
                region = split_mqtt[2];
            }
            this.log.debug(`MQTT UserID: ${this.mqtt_userID}`);
            const connectData = {
                caCert: Buffer.from(this.mqttdata.amazon, "utf-8"),
                privateKey: Buffer.from(this.mqttdata.privateKey, "utf-8"),
                clientCert: Buffer.from(this.mqttdata.certificatePem, "utf-8"),
                clientId: this.mqtt_userID,
                host: this.mqttdata.mqttServer,
                username: this.userNumber,
                region: region,
                debug: !!this.log.debug,
                baseReconnectTimeMs: 10000,
                keepalive: 60,
            };
            this.log.debug(`MQTT Connect Data: ${JSON.stringify(connectData)}`);

            this.mqttC = new awsIot(connectData);

            this.mqttC.on("offline", () => this.log.debug("Thinq MQTT offline"));
            this.mqttC.on("end", () => this.log.debug("Thinq MQTT end"));
            this.mqttC.on("close", () => this.log.debug("Thinq MQTT closed"));
            this.mqttC.on("disconnect", (packet) => {
                this.log.info(`MQTT disconnect: ${packet}`);
            });

            this.mqttC.on("connect", (packet) => {
                if (this.isRestart) {
                    this.log.info(`MQTT connected to subscriptions: ${JSON.stringify(this.mqttdata.subscriptions)}`);
                }
                this.isRestart = true;
                this.log.debug(`MQTT packet: ${JSON.stringify(packet)}`);
                for (const subscription of this.mqttdata.subscriptions) {
                    if (subscription) {
                        this.mqttC.subscribe(subscription);
                        this.log.debug(`Subscribed to MQTT topic: ${subscription}`);
                    } else {
                        this.log.warn(`Cannot find subscription - ${JSON.stringify(this.mqttdata)}`);
                    }
                }
                this.maskingTimer();
            });

            this.mqttC.on("reconnect", () => this.log.info("Thinq MQTT reconnect"));
            this.mqttC.on("message", async (topic, message) => {
                try {
                    const monitoring = JSON.parse(message);
                    this.log.debug(`Monitoring: ${JSON.stringify(monitoring)}`);
                    if (
                        monitoring &&
                        monitoring.data &&
                        monitoring.data.state &&
                        monitoring.data.state.reported &&
                        monitoring.type === "monitoring" &&
                        monitoring.deviceId
                    ) {
                        await this.json2iob.parse(`${monitoring.deviceId}.snapshot`, monitoring.data.state.reported, {
                            forceIndex: true,
                            write: true,
                            preferedArrayName: null,
                            channelName: null,
                            autoCast: true,
                            checkvalue: false,
                            checkType: true,
                            firstload: true,
                        });
                        if (
                            monitoring.data.state.reported.static &&
                            ["406", "401", "101"].includes(monitoring.data.state.reported.static.deviceType)
                        ) {
                            this.refreshRemote(monitoring);
                            if (monitoring.data.state.reported["airState.preHeat.schedule"] && !this.isAdapterUpdateFor406) {
                                this.updateHeat(monitoring.deviceId);
                            }
                        }
                    }
                } catch (error) {
                    this.log.info(`MQTT message parsing error: ${error.message}`);
                }
            });

            this.mqttC.on("error", (error) => {
                this.log.error(`MQTT ERROR: ${error.message}`);
            });
        } catch (error) {
            this.log.error(`MQTT ERROR: ${error.message}`);
            this.mqttC = null;
        }
    }

    /**
     * Holt Informationen für MQTT.
     * @param {string} requestUrl - Die URL für die Anfrage.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async getMqttInfo(requestUrl) {
        const headers = {
            "x-country-code": "DE",
            "x-service-phase": "OP",
        };
        this.log.debug(`Abrufen von MQTT Info von URL: ${requestUrl}`);
        try {
            const res = await this.requestClient.get(requestUrl, { headers });
            this.log.debug(`MQTT Info Antwort: ${JSON.stringify(res.data)}`);
            return res.data;
        } catch (error) {
            this.log.error(`getMqttInfo Fehler: ${error.message}`);
            if (error.response) {
                this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
            }
            return null;
        }
    }

    /**
     * Generiert eine UUID v4.
     * @returns {string} Eine UUID v4.
     */
    uuidv4() {
        const hex = crypto.randomBytes(16).toString("hex");
        return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`.toUpperCase();
    }

    /**
     * Holt Benutzerdaten.
     * @param {string} uri_value - Der URI-Wert.
     * @param {Object} data - Die Daten für die Anfrage.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async getUser(uri_value, data) {
        const userUrl = `${this.gateway.thinq2Uri}/${uri_value}`;
        const headers = { ...this.defaultHeaders, "x-client-id": this.mqtt_userID };
        this.log.debug(`Abrufen von User Info von URL: ${userUrl}`);
        this.log.debug(`User Info Daten: ${JSON.stringify(data)}`);
        this.log.debug(`User Info Headers: ${JSON.stringify(headers)}`);

        try {
            const resp = await this.requestClient.post(userUrl, data, { headers });
            this.log.debug(`User Info Antwort: ${JSON.stringify(resp.data)}`);
            return resp.data;
        } catch (error) {
            this.log.error(`getUser Fehler: ${error.message}`);
            if (error.response) {
                this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
            }
            return null;
        }
    }

    /**
     * Sendet einen Befehl an ein Gerät.
     * @param {string} deviceId - Die Geräte-ID.
     * @param {Object} values - Die Werte für den Befehl.
     * @param {boolean} thinq1 - Ob thinq1 verwendet wird.
     * @param {boolean} get_sync - Ob sync verwendet wird.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async sendCommandToDevice(deviceId, values, thinq1 = false, get_sync = false) {
        try {
            const headers = this.defaultHeaders;
            let sync = get_sync ? "control-sync" : "control";
            let controlUrl = `${this.gateway.thinq2Uri}/service/devices/${deviceId}/${sync}`;
            let data = {
                ctrlKey: "basicCtrl",
                command: "Set",
                ...values,
            };

            if (thinq1) {
                controlUrl = `${this.gateway.thinq1Uri}/rti/rtiControl`;
                data = values;
            }

            this.log.debug(`Sende Befehl an Gerät ${deviceId}: ${JSON.stringify(data)} an URL: ${controlUrl}`);

            const response = await this.requestClient.post(controlUrl, data, { headers });
            this.log.debug(`Antwort von Gerät ${deviceId}: ${JSON.stringify(response.data)}`);
            return response.data;
        } catch (error) {
            if (
                error.response &&
                error.response.status === 400 &&
                values.ctrlKey === "reservationCtrl" &&
                values.command === "Get"
            ) {
                this.log.debug(`Bad Request: ${error.message}`);
            } else {
                this.log.error(`SendCommandToDevice Fehler für Gerät ${deviceId}: ${error.message}`);
                if (error.response) {
                    this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
                }
            }
            return null;
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Wird aufgerufen, wenn sich ein abonnierter Zustand ändert.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {ioBroker.State | null | undefined} state - Der neue Zustand.
     */
    async onStateChange(id, state) {
        if (state && !state.ack) {
            try {
                const idParts = id.split(".");
                const lastElement = idParts.pop();
                const deviceId = idParts[2];
                const secsplit = idParts[idParts.length - 1];

                this.log.debug(`onStateChange für Gerät ${deviceId}: ${lastElement} = ${state.val}`);

                switch (lastElement) {
                    case "interval":
                        await this.setAckFlag(id);
                        await this.setNewInterval(state.val);
                        break;

                    case "ownrequest":
                        await this.ownRequestThinq1(state.val, deviceId);
                        await this.setAckFlag(id);
                        break;

                    case "sendJSON":
                    case "sendJSONNoSync":
                        await this.handleSendJSON(id, state, deviceId, lastElement);
                        break;

                    case "update":
                    case "unit":
                    case "device":
                        await this.handleWeatherStates(id, state, lastElement);
                        break;

                    default:
                        await this.handleDeviceCommands(id, state, deviceId, lastElement);
                        break;
                }
            } catch (e) {
                this.log.error(`onStateChange Fehler: ${e.message}`);
            }
        } else if (state && state.ack) {
            try {
                const idArray = id.split(".");
                const lastElement = idArray.pop();
                if (this.targetKeys[lastElement] && !id.includes(".remote.")) {
                    this.targetKeys[lastElement].forEach((element) => {
                        const newId = `${idArray.join(".")}.${element}`;
                        this.setStateAsync(newId, state.val, true);
                        this.log.debug(`Setze ack Zustand für ${newId} auf ${state.val}`);
                    });
                }
            } catch (e) {
                this.log.error(`Fehler bei ack States Verarbeitung: ${e.message}`);
            }
        }
    }

    /**
     * Behandelt das Senden von JSON-Daten an ein Gerät.
     */
    async handleSendJSON(id, state, deviceId, lastElement) {
        try {
            const sync = lastElement === "sendJSON" ? true : false;
            const controlsync = lastElement === "sendJSONNoSync" ? "/control" : "/control-sync";
            const headers = this.defaultHeaders;
            const controlUrl = `${this.gateway.thinq2Uri}/service/devices/${deviceId}${controlsync}`;
            const js = state.val ? state.val.toString() : "";
            let sendData;

            try {
                sendData = JSON.parse(js);
            } catch (e) {
                this.log.info(`JSON Parsing Fehler: ${e.message}`);
                return;
            }

            this.log.debug(`Sende JSON an Gerät ${deviceId}: ${JSON.stringify(sendData)}`);
            const sendJ = await this.sendCommandToDevice(deviceId, sendData, false, sync);

            this.log.info(`Antwort von Gerät ${deviceId}: ${JSON.stringify(sendJ)}`);
            await this.setAckFlag(id);
        } catch (error) {
            this.log.error(`handleSendJSON Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt Wetter-bezogene Zustandsänderungen.
     */
    async handleWeatherStates(id, state, lastElement) {
        try {
            if (lastElement === "device") {
                await this.setAckFlag(id);
            } else if (lastElement === "unit") {
                const units = state.val === "C" ? "°C" : "F";
                await this.extendObject(`weather.temperature`, { common: { unit: units } });
                await this.setAckFlag(id);
            } else if (lastElement === "update") {
                await this.getWeather();
                await this.setAckFlag(id, { val: false });
            }
        } catch (error) {
            this.log.error(`handleWeatherStates Fehler für ${id}: ${error.message}`);
        }
    }

    /**
     * Behandelt Befehle für verschiedene Gerätetypen.
     */
    async handleDeviceCommands(id, state, deviceId, lastElement) {
        try {
            const deviceModel = this.modelInfos[deviceId];
            if (!deviceModel) {
                this.log.warn(`Keine Modellinformationen für Gerät ${deviceId}`);
                return;
            }

            switch (deviceModel.deviceType) {
                case 401:
                    await this.handleDeviceType401Commands(id, state, deviceId, lastElement);
                    break;

                case 406:
                    await this.handleDeviceType406Commands(id, state, deviceId, lastElement);
                    break;

                default:
                    this.log.warn(`Unbekannter Gerätetyp ${deviceModel.deviceType} für Gerät ${deviceId}`);
                    break;
            }
        } catch (error) {
            this.log.error(`handleDeviceCommands Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt spezifische Befehle für Gerätetyp 401.
     */
    async handleDeviceType401Commands(id, state, deviceId, lastElement) {
        try {
            if (lastElement === "operation") {
                const action = state.val ? "Start" : "Stop";
                const data = {
                    ctrlKey: "Operation",
                    command: "Set",
                    dataKey: "operation",
                    dataValue: action,
                    dataSetList: null,
                    dataGetList: null,
                };
                this.log.debug(`Sende Befehl an Gerät 401 (${deviceId}): ${JSON.stringify(data)}`);
                const response = await this.sendCommandToDevice(deviceId, data, false, false);

                if (response && response.resultCode !== "0000") {
                    this.log.error(`Befehl an Gerät 401 (${deviceId}) fehlgeschlagen: ${JSON.stringify(response)}`);
                }

                await this.setAckFlag(id);
            } else {
                this.log.info(`Nicht implementierter Befehl ${lastElement} für Gerät 401 (${deviceId})`);
            }
        } catch (error) {
            this.log.error(`handleDeviceType401Commands Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt spezifische Befehle für Gerätetyp 406.
     */
    async handleDeviceType406Commands(id, state, deviceId, lastElement) {
        try {
            // Beispielhafte Verarbeitung für Gerätetyp 406
            // Implementiere hier die spezifischen Befehle für Gerätetyp 406
            if (lastElement === "add_new_schedule") {
                await this.addHeat(deviceId);
                await this.setAckFlag(id, { val: false });
                return;
            } else if (lastElement === "del_new_schedule") {
                await this.delHeat(deviceId, state.val);
                await this.setAckFlag(id);
                return;
            } else if (lastElement === "send_new_schedule") {
                await this.sendHeat(deviceId);
                await this.setAckFlag(id, { val: false });
                return;
            } else {
                this.log.info(`Nicht implementierter Befehl ${lastElement} für Gerätetyp 406 (${deviceId})`);
                return;
            }
        } catch (error) {
            this.log.error(`handleDeviceType406Commands Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Setzt ein neues Intervall für Thinq1.
     * @param {number} state - Der neue Intervallwert.
     */
    async setNewInterval(state) {
        if (!state) return;
        this.log.debug(`Setze neues Intervall: ${state}`);
        this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
        this.updateThinq1Interval = null;
        await this.sleep(1000);
        if (state === 0) {
            this.config.interval_thinq1 = 0;
        } else {
            this.config.interval_thinq1 = state;
            this.startPollMonitor();
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Erzeugt eine UUID v4.
     * @returns {string} Eine UUID v4.
     */
    uuidv4() {
        const hex = crypto.randomBytes(16).toString("hex");
        return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`.toUpperCase();
    }

    /**
     * Holt Benutzerdaten.
     * @param {string} uri_value - Der URI-Wert.
     * @param {Object} data - Die Daten für die Anfrage.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async getUser(uri_value, data) {
        const userUrl = `${this.gateway.thinq2Uri}/${uri_value}`;
        const headers = { ...this.defaultHeaders, "x-client-id": this.mqtt_userID };
        this.log.debug(`Abrufen von User Info von URL: ${userUrl}`);
        this.log.debug(`User Info Daten: ${JSON.stringify(data)}`);
        this.log.debug(`User Info Headers: ${JSON.stringify(headers)}`);

        try {
            const resp = await this.requestClient.post(userUrl, data, { headers });
            this.log.debug(`User Info Antwort: ${JSON.stringify(resp.data)}`);
            return resp.data;
        } catch (error) {
            this.log.error(`getUser Fehler: ${error.message}`);
            if (error.response) {
                this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
            }
            return null;
        }
    }

    /**
     * Sendet einen Befehl an ein Gerät.
     * @param {string} deviceId - Die Geräte-ID.
     * @param {Object} values - Die Werte für den Befehl.
     * @param {boolean} thinq1 - Ob thinq1 verwendet wird.
     * @param {boolean} get_sync - Ob sync verwendet wird.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async sendCommandToDevice(deviceId, values, thinq1 = false, get_sync = false) {
        try {
            const headers = this.defaultHeaders;
            let sync = get_sync ? "control-sync" : "control";
            let controlUrl = `${this.gateway.thinq2Uri}/service/devices/${deviceId}/${sync}`;
            let data = {
                ctrlKey: "basicCtrl",
                command: "Set",
                ...values,
            };

            if (thinq1) {
                controlUrl = `${this.gateway.thinq1Uri}/rti/rtiControl`;
                data = values;
            }

            this.log.debug(`Sende Befehl an Gerät ${deviceId}: ${JSON.stringify(data)} an URL: ${controlUrl}`);

            const response = await this.requestClient.post(controlUrl, data, { headers });
            this.log.debug(`Antwort von Gerät ${deviceId}: ${JSON.stringify(response.data)}`);
            return response.data;
        } catch (error) {
            if (
                error.response &&
                error.response.status === 400 &&
                values.ctrlKey === "reservationCtrl" &&
                values.command === "Get"
            ) {
                this.log.debug(`Bad Request: ${error.message}`);
            } else {
                this.log.error(`SendCommandToDevice Fehler für Gerät ${deviceId}: ${error.message}`);
                if (error.response) {
                    this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
                }
            }
            return null;
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Wird aufgerufen, wenn sich ein abonnierter Zustand ändert.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {ioBroker.State | null | undefined} state - Der neue Zustand.
     */
    async onStateChange(id, state) {
        if (state && !state.ack) {
            try {
                const idParts = id.split(".");
                const lastElement = idParts.pop();
                const deviceId = idParts[2];
                const secsplit = idParts[idParts.length - 1];

                this.log.debug(`onStateChange für Gerät ${deviceId}: ${lastElement} = ${state.val}`);

                switch (lastElement) {
                    case "interval":
                        await this.setAckFlag(id);
                        await this.setNewInterval(state.val);
                        break;

                    case "ownrequest":
                        await this.ownRequestThinq1(state.val, deviceId);
                        await this.setAckFlag(id);
                        break;

                    case "sendJSON":
                    case "sendJSONNoSync":
                        await this.handleSendJSON(id, state, deviceId, lastElement);
                        break;

                    case "update":
                    case "unit":
                    case "device":
                        await this.handleWeatherStates(id, state, lastElement);
                        break;

                    default:
                        await this.handleDeviceCommands(id, state, deviceId, lastElement);
                        break;
                }
            } catch (e) {
                this.log.error(`onStateChange Fehler: ${e.message}`);
            }
        } else if (state && state.ack) {
            try {
                const idArray = id.split(".");
                const lastElement = idArray.pop();
                if (this.targetKeys[lastElement] && !id.includes(".remote.")) {
                    this.targetKeys[lastElement].forEach((element) => {
                        const newId = `${idArray.join(".")}.${element}`;
                        this.setStateAsync(newId, state.val, true);
                        this.log.debug(`Setze ack Zustand für ${newId} auf ${state.val}`);
                    });
                }
            } catch (e) {
                this.log.error(`Fehler bei ack States Verarbeitung: ${e.message}`);
            }
        }
    }

    /**
     * Setzt ein neues Intervall für Thinq1.
     * @param {number} state - Der neue Intervallwert.
     */
    async setNewInterval(state) {
        if (!state) return;
        this.log.debug(`Setze neues Intervall: ${state}`);
        this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
        this.updateThinq1Interval = null;
        await this.sleep(1000);
        if (state === 0) {
            this.config.interval_thinq1 = 0;
        } else {
            this.config.interval_thinq1 = state;
            this.startPollMonitor();
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Extrahiert Werte aus dem Geräte-Modell und erstellt Datenpunkte.
     * @param {Object} device - Das Gerät.
     */
    async extractValues(device) {
        const deviceModel = this.modelInfos[device.deviceId];
        if (!deviceModel) {
            this.log.warn(`Keine Modellinformationen für Gerät ${device.deviceId}`);
            return;
        }

        let langPack = null;
        let langPath = device.langPackProductTypeUri ? "langPackProductTypeUri" : 
                       device.langPackModelUri ? "langPackModelUri" : null;

        if (langPath) {
            langPack = await this.requestClient.get(device[langPath])
                .then(res => res.data)
                .catch(error => {
                    this.log.info(`Fehler beim Abrufen des Sprachpakets für Gerät ${device.deviceId}: ${error}`);
                    return null;
                });
        }

        if (deviceModel["MonitoringValue"] || deviceModel["Value"]) {
            this.log.debug("Extrahiere Werte aus dem Modell");
            const deviceType = deviceModel["deviceType"] || 0;
            let type = "";

            if (device.snapshot && deviceModel["folder"] && deviceType !== 401) {
                type = deviceModel["folder"];
            }

            let path = `${device.deviceId}.snapshot.`;
            if (type) {
                path += `${type}.`;
            }

            if (deviceType === 202) {
                await this.setDryerBlindStates(path);
            }

            const downloadedCourseType = this.coursetypes[device.deviceId]?.downloadedCourseType || "courseType";
            const smartCourseType = this.coursetypes[device.deviceId]?.smartCourseType || "WASHERANDDRYER";
            const courseType = this.coursetypes[device.deviceId]?.courseType || "WASHERANDDRYER";
            const onlynumber = /^-?[0-9]+$/;

            if (deviceModel["MonitoringValue"]) {
                for (const state in deviceModel["MonitoringValue"]) {
                    const fullPath = `${path}${state}`;
                    this.log.debug(`Verarbeite Datenpunkt: ${fullPath}`);

                    let obj;
                    try {
                        obj = await this.getObjectAsync(fullPath);
                        if (!obj) {
                            this.log.warn(`Datenpunkt ${fullPath} existiert nicht. Überspringen.`);
                            continue;
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Abrufen des Objekts ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const common = { ...obj.common };
                    const commons = {};
                    let valueObject = deviceModel["MonitoringValue"][state]?.option || null;
                    const valueDefault = deviceModel["MonitoringValue"][state]?.default || null;

                    if (deviceModel["MonitoringValue"][state]?.value_mapping) {
                        valueObject = deviceModel["MonitoringValue"][state].value_mapping;
                    }
                    if (deviceModel["MonitoringValue"][state]?.value_validation) {
                        valueObject = deviceModel["MonitoringValue"][state].value_validation;
                    }

                    if (valueObject && typeof valueObject === "object") {
                        if (valueObject.max) {
                            common.min = 0;
                            switch (state) {
                                case "moreLessTime":
                                    common.max = 200;
                                    break;
                                case "timeSetting":
                                    common.max = 360;
                                    break;
                                case "AirPolution":
                                case "airState.quality.odor":
                                    common.max = 2000000;
                                    break;
                                case "airState.miscFuncState.autoDryRemainTime":
                                    common.max = 300;
                                    break;
                                default:
                                    common.max = (valueDefault != null && valueDefault > valueObject.max) ? valueDefault : valueObject.max;
                                    break;
                            }
                            common.def = valueDefault ? parseFloat(valueDefault) : 0;
                        } else {
                            const values = Object.keys(valueObject);
                            for (const value of values) {
                                const content = valueObject[value];
                                if (typeof content === "string") {
                                    const new_content = content.replace("@", "");
                                    if (langPack?.[content]) {
                                        commons[value] = langPack[content].toString("utf-8");
                                    } else if (constants[`${this.lang}Translation`]?.[new_content]) {
                                        commons[value] = constants[`${this.lang}Translation`][new_content];
                                    } else {
                                        commons[value] = new_content;
                                    }
                                }
                            }
                        }
                    }

                    if (Object.keys(commons).length > 0) {
                        common.states = commons;
                    }

                    try {
                        if (!obj) {
                            await this.setObjectNotExistsAsync(fullPath, {
                                type: "state",
                                common: common,
                                native: {},
                            }).catch((error) => {
                                this.log.error(`Fehler beim Erstellen des Datenpunkts ${fullPath}: ${error}`);
                            });
                        } else {
                            obj.common = common;
                            await this.setObjectAsync(fullPath, obj).catch((error) => {
                                this.log.error(`Fehler beim Aktualisieren des Datenpunkts ${fullPath}: ${error}`);
                            });
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Verarbeiten des Datenpunkts ${fullPath}: ${error.message}`);
                    }
                }
            }

            if (deviceModel["Value"]) {
                for (const state in deviceModel["Value"]) {
                    const fullPath = `${path}${state}`;
                    this.log.debug(`Verarbeite Value-Datenpunkt: ${fullPath} (Problem mit 401 device)`);

                    let obj;
                    try {
                        obj = await this.getObjectAsync(fullPath);
                        if (!obj) {
                            this.log.warn(`Value-Datenpunkt ${fullPath} existiert nicht. Überspringen.`);
                            continue;
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Abrufen des Value-Objekts ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const common = { ...obj.common };
                    const commons = {};
                    let valueObject = deviceModel["Value"][state]?.option || null;
                    const valueDefault = deviceModel["Value"][state]?.default || null;

                    if (deviceModel["Value"][state]?.value_mapping) {
                        valueObject = deviceModel["Value"][state].value_mapping;
                    }
                    if (deviceModel["Value"][state]?.value_validation) {
                        valueObject = deviceModel["Value"][state].value_validation;
                    }

                    if (valueObject && typeof valueObject === "object") {
                        if (valueObject.max) {
                            common.min = 0;
                            switch (state) {
                                case "moreLessTime":
                                    common.max = 200;
                                    break;
                                case "timeSetting":
                                    common.max = 360;
                                    break;
                                case "AirPolution":
                                case "airState.quality.odor":
                                    common.max = 2000000;
                                    break;
                                case "airState.miscFuncState.autoDryRemainTime":
                                    common.max = 300;
                                    break;
                                default:
                                    common.max = (valueDefault != null && valueDefault > valueObject.max) ? valueDefault : valueObject.max;
                                    break;
                            }
                            common.def = valueDefault ? parseFloat(valueDefault) : 0;
                        } else {
                            const values = Object.keys(valueObject);
                            for (const value of values) {
                                const content = valueObject[value];
                                if (typeof content === "string") {
                                    const new_content = content.replace("@", "");
                                    if (langPack?.[content]) {
                                        commons[value] = langPack[content].toString("utf-8");
                                    } else if (constants[`${this.lang}Translation`]?.[new_content]) {
                                        commons[value] = constants[`${this.lang}Translation`][new_content];
                                    } else {
                                        commons[value] = new_content;
                                    }
                                }
                            }
                        }
                    }

                    if (Object.keys(commons).length > 0) {
                        common.states = commons;
                    }

                    try {
                        if (!obj) {
                            await this.setObjectNotExistsAsync(fullPath, {
                                type: "state",
                                common: common,
                                native: {},
                            }).catch((error) => {
                                this.log.error(`Fehler beim Erstellen des Value-Datenpunkts ${fullPath}: ${error}`);
                            });
                        } else {
                            obj.common = common;
                            await this.setObjectAsync(fullPath, obj).catch((error) => {
                                this.log.error(`Fehler beim Aktualisieren des Value-Datenpunkts ${fullPath}: ${error}`);
                            });
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Verarbeiten des Value-Datenpunkts ${fullPath}: ${error.message}`);
                    }
                }
            }
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Wird aufgerufen, wenn sich ein abonnierter Zustand ändert.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {ioBroker.State | null | undefined} state - Der neue Zustand.
     */
    async onStateChange(id, state) {
        if (state && !state.ack) {
            try {
                const idParts = id.split(".");
                const lastElement = idParts.pop();
                const deviceId = idParts[2];
                const secsplit = idParts[idParts.length - 1];

                this.log.debug(`onStateChange für Gerät ${deviceId}: ${lastElement} = ${state.val}`);

                switch (lastElement) {
                    case "interval":
                        await this.setAckFlag(id);
                        await this.setNewInterval(state.val);
                        break;

                    case "ownrequest":
                        await this.ownRequestThinq1(state.val, deviceId);
                        await this.setAckFlag(id);
                        break;

                    case "sendJSON":
                    case "sendJSONNoSync":
                        await this.handleSendJSON(id, state, deviceId, lastElement);
                        break;

                    case "update":
                    case "unit":
                    case "device":
                        await this.handleWeatherStates(id, state, lastElement);
                        break;

                    default:
                        await this.handleDeviceCommands(id, state, deviceId, lastElement);
                        break;
                }
            } catch (e) {
                this.log.error(`onStateChange Fehler: ${e.message}`);
            }
        } else if (state && state.ack) {
            try {
                const idArray = id.split(".");
                const lastElement = idArray.pop();
                if (this.targetKeys[lastElement] && !id.includes(".remote.")) {
                    this.targetKeys[lastElement].forEach((element) => {
                        const newId = `${idArray.join(".")}.${element}`;
                        this.setStateAsync(newId, state.val, true);
                        this.log.debug(`Setze ack Zustand für ${newId} auf ${state.val}`);
                    });
                }
            } catch (e) {
                this.log.error(`Fehler bei ack States Verarbeitung: ${e.message}`);
            }
        }
    }

    /**
     * Behandelt spezifische Befehle für verschiedene Gerätetypen.
     */
    async handleDeviceCommands(id, state, deviceId, lastElement) {
        try {
            const deviceModel = this.modelInfos[deviceId];
            if (!deviceModel) {
                this.log.warn(`Keine Modellinformationen für Gerät ${deviceId}`);
                return;
            }

            switch (deviceModel.deviceType) {
                case 401:
                    await this.handleDeviceType401Commands(id, state, deviceId, lastElement);
                    break;

                case 406:
                    await this.handleDeviceType406Commands(id, state, deviceId, lastElement);
                    break;

                default:
                    this.log.warn(`Unbekannter Gerätetyp ${deviceModel.deviceType} für Gerät ${deviceId}`);
                    break;
            }
        } catch (error) {
            this.log.error(`handleDeviceCommands Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt spezifische Befehle für Gerätetyp 401.
     */
    async handleDeviceType401Commands(id, state, deviceId, lastElement) {
        try {
            if (lastElement === "operation") {
                const action = state.val ? "Start" : "Stop";
                const data = {
                    ctrlKey: "Operation",
                    command: "Set",
                    dataKey: "operation",
                    dataValue: action,
                    dataSetList: null,
                    dataGetList: null,
                };
                this.log.debug(`Sende Befehl an Gerät 401 (${deviceId}): ${JSON.stringify(data)}`);
                const response = await this.sendCommandToDevice(deviceId, data, false, false);

                if (response && response.resultCode !== "0000") {
                    this.log.error(`Befehl an Gerät 401 (${deviceId}) fehlgeschlagen: ${JSON.stringify(response)}`);
                }

                await this.setAckFlag(id);
            } else {
                this.log.info(`Nicht implementierter Befehl ${lastElement} für Gerät 401 (${deviceId})`);
            }
        } catch (error) {
            this.log.error(`handleDeviceType401Commands Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt spezifische Befehle für Gerätetyp 406.
     */
    async handleDeviceType406Commands(id, state, deviceId, lastElement) {
        try {
            // Beispielhafte Verarbeitung für Gerätetyp 406
            if (lastElement === "add_new_schedule") {
                await this.addHeat(deviceId);
                await this.setAckFlag(id, { val: false });
                return;
            } else if (lastElement === "del_new_schedule") {
                await this.delHeat(deviceId, state.val);
                await this.setAckFlag(id);
                return;
            } else if (lastElement === "send_new_schedule") {
                await this.sendHeat(deviceId);
                await this.setAckFlag(id, { val: false });
                return;
            } else {
                this.log.info(`Nicht implementierter Befehl ${lastElement} für Gerätetyp 406 (${deviceId})`);
                return;
            }
        } catch (error) {
            this.log.error(`handleDeviceType406Commands Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt das Senden von JSON-Daten an ein Gerät.
     */
    async handleSendJSON(id, state, deviceId, lastElement) {
        try {
            const sync = lastElement === "sendJSON" ? true : false;
            const controlsync = lastElement === "sendJSONNoSync" ? "/control" : "/control-sync";
            const headers = this.defaultHeaders;
            const controlUrl = `${this.gateway.thinq2Uri}/service/devices/${deviceId}${controlsync}`;
            const js = state.val ? state.val.toString() : "";
            let sendData;

            try {
                sendData = JSON.parse(js);
            } catch (e) {
                this.log.info(`JSON Parsing Fehler: ${e.message}`);
                return;
            }

            this.log.debug(`Sende JSON an Gerät ${deviceId}: ${JSON.stringify(sendData)}`);
            const sendJ = await this.sendCommandToDevice(deviceId, sendData, false, sync);

            this.log.info(`Antwort von Gerät ${deviceId}: ${JSON.stringify(sendJ)}`);
            await this.setAckFlag(id);
        } catch (error) {
            this.log.error(`handleSendJSON Fehler für Gerät ${deviceId}: ${error.message}`);
        }
    }

    /**
     * Behandelt Wetter-bezogene Zustandsänderungen.
     */
    async handleWeatherStates(id, state, lastElement) {
        try {
            if (lastElement === "device") {
                await this.setAckFlag(id);
            } else if (lastElement === "unit") {
                const units = state.val === "C" ? "°C" : "F";
                await this.extendObject(`weather.temperature`, { common: { unit: units } });
                await this.setAckFlag(id);
            } else if (lastElement === "update") {
                await this.getWeather();
                await this.setAckFlag(id, { val: false });
            }
        } catch (error) {
            this.log.error(`handleWeatherStates Fehler für ${id}: ${error.message}`);
        }
    }

    /**
     * Extrahiert Werte aus dem Geräte-Modell und erstellt Datenpunkte.
     * @param {Object} device - Das Gerät.
     */
    async extractValues(device) {
        const deviceModel = this.modelInfos[device.deviceId];
        if (!deviceModel) {
            this.log.warn(`Keine Modellinformationen für Gerät ${device.deviceId}`);
            return;
        }

        let langPack = null;
        let langPath = device.langPackProductTypeUri ? "langPackProductTypeUri" : 
                       device.langPackModelUri ? "langPackModelUri" : null;

        if (langPath) {
            langPack = await this.requestClient.get(device[langPath])
                .then(res => res.data)
                .catch(error => {
                    this.log.info(`Fehler beim Abrufen des Sprachpakets für Gerät ${device.deviceId}: ${error}`);
                    return null;
                });
        }

        if (deviceModel["MonitoringValue"] || deviceModel["Value"]) {
            this.log.debug("Extrahiere Werte aus dem Modell");
            const deviceType = deviceModel["deviceType"] || 0;
            let type = "";

            if (device.snapshot && deviceModel["folder"] && deviceType !== 401) {
                type = deviceModel["folder"];
            }

            let path = `${device.deviceId}.snapshot.`;
            if (type) {
                path += `${type}.`;
            }

            if (deviceType === 202) {
                await this.setDryerBlindStates(path);
            }

            const downloadedCourseType = this.coursetypes[device.deviceId]?.downloadedCourseType || "courseType";
            const smartCourseType = this.coursetypes[device.deviceId]?.smartCourseType || "WASHERANDDRYER";
            const courseType = this.coursetypes[device.deviceId]?.courseType || "WASHERANDDRYER";
            const onlynumber = /^-?[0-9]+$/;

            if (deviceModel["MonitoringValue"]) {
                for (const state in deviceModel["MonitoringValue"]) {
                    const fullPath = `${path}${state}`;
                    this.log.debug(`Verarbeite Datenpunkt: ${fullPath}`);

                    let obj;
                    try {
                        obj = await this.getObjectAsync(fullPath);
                        if (!obj) {
                            this.log.warn(`Datenpunkt ${fullPath} existiert nicht. Überspringen.`);
                            continue;
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Abrufen des Objekts ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const common = { ...obj.common };
                    const commons = {};
                    let valueObject = deviceModel["MonitoringValue"][state]?.option || null;
                    const valueDefault = deviceModel["MonitoringValue"][state]?.default || null;

                    if (deviceModel["MonitoringValue"][state]?.value_mapping) {
                        valueObject = deviceModel["MonitoringValue"][state].value_mapping;
                    }
                    if (deviceModel["MonitoringValue"][state]?.value_validation) {
                        valueObject = deviceModel["MonitoringValue"][state].value_validation;
                    }

                    if (valueObject && typeof valueObject === "object") {
                        if (valueObject.max) {
                            common.min = 0;
                            switch (state) {
                                case "moreLessTime":
                                    common.max = 200;
                                    break;
                                case "timeSetting":
                                    common.max = 360;
                                    break;
                                case "AirPolution":
                                case "airState.quality.odor":
                                    common.max = 2000000;
                                    break;
                                case "airState.miscFuncState.autoDryRemainTime":
                                    common.max = 300;
                                    break;
                                default:
                                    common.max = (valueDefault != null && valueDefault > valueObject.max) ? valueDefault : valueObject.max;
                                    break;
                            }
                            common.def = valueDefault ? parseFloat(valueDefault) : 0;
                        } else {
                            const values = Object.keys(valueObject);
                            for (const value of values) {
                                const content = valueObject[value];
                                if (typeof content === "string") {
                                    const new_content = content.replace("@", "");
                                    if (langPack?.[content]) {
                                        commons[value] = langPack[content].toString("utf-8");
                                    } else if (constants[`${this.lang}Translation`]?.[new_content]) {
                                        commons[value] = constants[`${this.lang}Translation`][new_content];
                                    } else {
                                        commons[value] = new_content;
                                    }
                                }
                            }
                        }
                    }

                    if (Object.keys(commons).length > 0) {
                        common.states = commons;
                    }

                    try {
                        if (!obj) {
                            await this.setObjectNotExistsAsync(fullPath, {
                                type: "state",
                                common: common,
                                native: {},
                            }).catch((error) => {
                                this.log.error(`Fehler beim Erstellen des Datenpunkts ${fullPath}: ${error}`);
                            });
                        } else {
                            obj.common = common;
                            await this.setObjectAsync(fullPath, obj).catch((error) => {
                                this.log.error(`Fehler beim Aktualisieren des Datenpunkts ${fullPath}: ${error}`);
                            });
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Verarbeiten des Datenpunkts ${fullPath}: ${error.message}`);
                    }
                }
            }

            if (deviceModel["Value"]) {
                for (const state in deviceModel["Value"]) {
                    const fullPath = `${path}${state}`;
                    this.log.debug(`Verarbeite Value-Datenpunkt: ${fullPath} (Problem mit 401 device)`);

                    let obj;
                    try {
                        obj = await this.getObjectAsync(fullPath);
                        if (!obj) {
                            this.log.warn(`Value-Datenpunkt ${fullPath} existiert nicht. Überspringen.`);
                            continue;
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Abrufen des Value-Objekts ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const common = { ...obj.common };
                    const commons = {};
                    let valueObject = deviceModel["Value"][state]?.option || null;
                    const valueDefault = deviceModel["Value"][state]?.default || null;

                    if (deviceModel["Value"][state]?.value_mapping) {
                        valueObject = deviceModel["Value"][state].value_mapping;
                    }
                    if (deviceModel["Value"][state]?.value_validation) {
                        valueObject = deviceModel["Value"][state].value_validation;
                    }

                    if (valueObject && typeof valueObject === "object") {
                        if (valueObject.max) {
                            common.min = 0;
                            switch (state) {
                                case "moreLessTime":
                                    common.max = 200;
                                    break;
                                case "timeSetting":
                                    common.max = 360;
                                    break;
                                case "AirPolution":
                                case "airState.quality.odor":
                                    common.max = 2000000;
                                    break;
                                case "airState.miscFuncState.autoDryRemainTime":
                                    common.max = 300;
                                    break;
                                default:
                                    common.max = (valueDefault != null && valueDefault > valueObject.max) ? valueDefault : valueObject.max;
                                    break;
                            }
                            common.def = valueDefault ? parseFloat(valueDefault) : 0;
                        } else {
                            const values = Object.keys(valueObject);
                            for (const value of values) {
                                const content = valueObject[value];
                                if (typeof content === "string") {
                                    const new_content = content.replace("@", "");
                                    if (langPack?.[content]) {
                                        commons[value] = langPack[content].toString("utf-8");
                                    } else if (constants[`${this.lang}Translation`]?.[new_content]) {
                                        commons[value] = constants[`${this.lang}Translation`][new_content];
                                    } else {
                                        commons[value] = new_content;
                                    }
                                }
                            }
                        }
                    }

                    if (Object.keys(commons).length > 0) {
                        common.states = commons;
                    }

                    try {
                        if (!obj) {
                            await this.setObjectNotExistsAsync(fullPath, {
                                type: "state",
                                common: common,
                                native: {},
                            }).catch((error) => {
                                this.log.error(`Fehler beim Erstellen des Value-Datenpunkts ${fullPath}: ${error}`);
                            });
                        } else {
                            obj.common = common;
                            await this.setObjectAsync(fullPath, obj).catch((error) => {
                                this.log.error(`Fehler beim Aktualisieren des Value-Datenpunkts ${fullPath}: ${error}`);
                            });
                        }
                    } catch (error) {
                        this.log.error(`Fehler beim Verarbeiten des Value-Datenpunkts ${fullPath}: ${error.message}`);
                    }
                }
            }
        }
    }

    /**
     * Startet den MQTT-Client mit verbesserter Fehlerbehandlung und Logging.
     */
    async start_mqtt() {
        try {
            if (!this.mqttdata.privateKey) {
                const mqttHost = await this.getMqttInfo(constants.MQTT_URL);
                let mqttHostParts = [];
                if (mqttHost && mqttHost.result && mqttHost.result.mqttServer) {
                    if (mqttHost.result.apiServer && !mqttHost.result.apiServer.includes("-ats.iot")) {
                        mqttHostParts = mqttHost.result.mqttServer.split(".iot.");
                        this.mqttdata["apiServer"] = `${mqttHostParts[0]}-ats.iot.${mqttHostParts[1]}`;
                    }
                    if (!mqttHost.result.mqttServer.includes("-ats.iot")) {
                        mqttHostParts = mqttHost.result.mqttServer.split(".iot.");
                        this.mqttdata["mqttServer"] = `${mqttHostParts[0]}-ats.iot.${mqttHostParts[1]}`;
                    }
                } else {
                    this.log.info("Cannot load MQTT Host");
                    return;
                }
                this.log.info("Found MQTT Host");
                this.mqttdata.mqttServer = this.resolveUrl(this.mqttdata.mqttServer, "", true);
                const mqttCer = await this.getMqttInfo(constants.MQTT_CER);
                if (!mqttCer) {
                    this.log.info("Cannot load AWS CER");
                    return;
                }
                this.mqttdata.amazon = mqttCer;
                this.log.info("Found AWS CER");
                const certGenerator = await this.getMqttInfo(constants.MQTT_AZU);
                if (certGenerator.privKey && certGenerator.csr) {
                    this.mqttdata.privateKey = certGenerator.privKey;
                    this.mqttdata.key = certGenerator.csr;
                } else {
                    const key = forge.pki.rsa.generateKeyPair(2048);
                    const keys = {};
                    keys.privateKey = forge.pki.privateKeyToPem(key.privateKey);
                    this.mqttdata.privateKey = keys.privateKey;
                    keys.publicKey = forge.pki.publicKeyToPem(key.publicKey);
                    const csr = forge.pki.createCertificationRequest();
                    csr.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
                    csr.setSubject([
                        {
                            shortName: "CN",
                            value: "AWS IoT Certificate",
                        },
                        {
                            shortName: "O",
                            value: "Amazon",
                        },
                    ]);
                    csr.sign(forge.pki.privateKeyFromPem(keys.privateKey), forge.md.sha256.create());
                    this.mqttdata.key = forge.pki.certificationRequestToPem(csr);
                }
                this.log.info("Create certification done");
            }

            await this.getUser("service/users/client", {});
            const client_certificate = await this.getUser("service/users/client/certificate", {
                csr: this.mqttdata.key,
            });
            if (!client_certificate || !client_certificate.result || !client_certificate.result.certificatePem) {
                this.log.info("Cannot load certificatePem");
                return;
            }
            if (!client_certificate.result.subscriptions) {
                this.log.info("Cannot load subscriptions");
                return;
            }
            this.mqttdata.certificatePem = client_certificate.result.certificatePem;
            this.mqttdata.subscriptions = client_certificate.result.subscriptions;
            if (this.isRestart) {
                this.log.info("Start MQTT Connection");
            }
            this.connectMqtt();
        } catch (error) {
            this.log.error(`Create CSR ERROR: ${error.message}`);
            this.mqttC = null;
            this.isRestart = true;
            if (error.message.indexOf("0110") === -1) {
                this.terms();
            }
        }
    }

    /**
     * Verbindet den MQTT-Client mit verbesserter Fehlerbehandlung und Logging.
     */
    async connectMqtt() {
        try {
            let region = "eu-west-1";
            const split_mqtt = this.mqttdata.mqttServer.split(".");
            if (split_mqtt.length > 1) {
                region = split_mqtt[2];
            }
            this.log.debug(`MQTT UserID: ${this.mqtt_userID}`);
            const connectData = {
                caCert: Buffer.from(this.mqttdata.amazon, "utf-8"),
                privateKey: Buffer.from(this.mqttdata.privateKey, "utf-8"),
                clientCert: Buffer.from(this.mqttdata.certificatePem, "utf-8"),
                clientId: this.mqtt_userID,
                host: this.mqttdata.mqttServer,
                username: this.userNumber,
                region: region,
                debug: !!this.log.debug,
                baseReconnectTimeMs: 10000,
                keepalive: 60,
            };
            this.log.debug(`MQTT Connect Data: ${JSON.stringify(connectData)}`);

            this.mqttC = new awsIot(connectData);

            this.mqttC.on("offline", () => this.log.debug("Thinq MQTT offline"));
            this.mqttC.on("end", () => this.log.debug("Thinq MQTT end"));
            this.mqttC.on("close", () => this.log.debug("Thinq MQTT closed"));
            this.mqttC.on("disconnect", (packet) => {
                this.log.info(`MQTT disconnect: ${packet}`);
            });

            this.mqttC.on("connect", (packet) => {
                if (this.isRestart) {
                    this.log.info(`MQTT connected to subscriptions: ${JSON.stringify(this.mqttdata.subscriptions)}`);
                }
                this.isRestart = true;
                this.log.debug(`MQTT packet: ${JSON.stringify(packet)}`);
                for (const subscription of this.mqttdata.subscriptions) {
                    if (subscription) {
                        this.mqttC.subscribe(subscription);
                        this.log.debug(`Subscribed to MQTT topic: ${subscription}`);
                    } else {
                        this.log.warn(`Cannot find subscription - ${JSON.stringify(this.mqttdata)}`);
                    }
                }
                this.maskingTimer();
            });

            this.mqttC.on("reconnect", () => this.log.info("Thinq MQTT reconnect"));
            this.mqttC.on("message", async (topic, message) => {
                try {
                    const monitoring = JSON.parse(message);
                    this.log.debug(`Monitoring: ${JSON.stringify(monitoring)}`);
                    if (
                        monitoring &&
                        monitoring.data &&
                        monitoring.data.state &&
                        monitoring.data.state.reported &&
                        monitoring.type === "monitoring" &&
                        monitoring.deviceId
                    ) {
                        await this.json2iob.parse(`${monitoring.deviceId}.snapshot`, monitoring.data.state.reported, {
                            forceIndex: true,
                            write: true,
                            preferedArrayName: null,
                            channelName: null,
                            autoCast: true,
                            checkvalue: false,
                            checkType: true,
                            firstload: true,
                        });
                        if (
                            monitoring.data.state.reported.static &&
                            ["406", "401", "101"].includes(monitoring.data.state.reported.static.deviceType)
                        ) {
                            this.refreshRemote(monitoring);
                            if (monitoring.data.state.reported["airState.preHeat.schedule"] && !this.isAdapterUpdateFor406) {
                                this.updateHeat(monitoring.deviceId);
                            }
                        }
                    }
                } catch (error) {
                    this.log.info(`MQTT message parsing error: ${error.message}`);
                }
            });

            this.mqttC.on("error", (error) => {
                this.log.error(`MQTT ERROR: ${error.message}`);
            });
        } catch (error) {
            this.log.error(`MQTT ERROR: ${error.message}`);
            this.mqttC = null;
        }
    }

    /**
     * Holt Informationen für MQTT.
     * @param {string} requestUrl - Die URL für die Anfrage.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async getMqttInfo(requestUrl) {
        const headers = {
            "x-country-code": "DE",
            "x-service-phase": "OP",
        };
        this.log.debug(`Abrufen von MQTT Info von URL: ${requestUrl}`);
        try {
            const res = await this.requestClient.get(requestUrl, { headers });
            this.log.debug(`MQTT Info Antwort: ${JSON.stringify(res.data)}`);
            return res.data;
        } catch (error) {
            this.log.error(`getMqttInfo Fehler: ${error.message}`);
            if (error.response) {
                this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
            }
            return null;
        }
    }

    /**
     * Erzeugt eine UUID v4.
     * @returns {string} Eine UUID v4.
     */
    uuidv4() {
        const hex = crypto.randomBytes(16).toString("hex");
        return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`.toUpperCase();
    }

    /**
     * Holt Benutzerdaten.
     * @param {string} uri_value - Der URI-Wert.
     * @param {Object} data - Die Daten für die Anfrage.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async getUser(uri_value, data) {
        const userUrl = `${this.gateway.thinq2Uri}/${uri_value}`;
        const headers = { ...this.defaultHeaders, "x-client-id": this.mqtt_userID };
        this.log.debug(`Abrufen von User Info von URL: ${userUrl}`);
        this.log.debug(`User Info Daten: ${JSON.stringify(data)}`);
        this.log.debug(`User Info Headers: ${JSON.stringify(headers)}`);

        try {
            const resp = await this.requestClient.post(userUrl, data, { headers });
            this.log.debug(`User Info Antwort: ${JSON.stringify(resp.data)}`);
            return resp.data;
        } catch (error) {
            this.log.error(`getUser Fehler: ${error.message}`);
            if (error.response) {
                this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
            }
            return null;
        }
    }

    /**
     * Sendet einen Befehl an ein Gerät.
     * @param {string} deviceId - Die Geräte-ID.
     * @param {Object} values - Die Werte für den Befehl.
     * @param {boolean} thinq1 - Ob thinq1 verwendet wird.
     * @param {boolean} get_sync - Ob sync verwendet wird.
     * @returns {Promise<Object|null>} Die API-Antwort oder null bei Fehlern.
     */
    async sendCommandToDevice(deviceId, values, thinq1 = false, get_sync = false) {
        try {
            const headers = this.defaultHeaders;
            let sync = get_sync ? "control-sync" : "control";
            let controlUrl = `${this.gateway.thinq2Uri}/service/devices/${deviceId}/${sync}`;
            let data = {
                ctrlKey: "basicCtrl",
                command: "Set",
                ...values,
            };

            if (thinq1) {
                controlUrl = `${this.gateway.thinq1Uri}/rti/rtiControl`;
                data = values;
            }

            this.log.debug(`Sende Befehl an Gerät ${deviceId}: ${JSON.stringify(data)} an URL: ${controlUrl}`);

            const response = await this.requestClient.post(controlUrl, data, { headers });
            this.log.debug(`Antwort von Gerät ${deviceId}: ${JSON.stringify(response.data)}`);
            return response.data;
        } catch (error) {
            if (
                error.response &&
                error.response.status === 400 &&
                values.ctrlKey === "reservationCtrl" &&
                values.command === "Get"
            ) {
                this.log.debug(`Bad Request: ${error.message}`);
            } else {
                this.log.error(`SendCommandToDevice Fehler für Gerät ${deviceId}: ${error.message}`);
                if (error.response) {
                    this.log.error(`Antwort der API: ${JSON.stringify(error.response.data)}`);
                }
            }
            return null;
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Erzeugt eine UUID v4.
     * @returns {string} Eine UUID v4.
     */
    uuidv4() {
        const hex = crypto.randomBytes(16).toString("hex");
        return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`.toUpperCase();
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Wird aufgerufen, wenn der Adapter beendet wird.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Setzt das Ack-Flag für einen Datenpunkt.
     * @param {string} id - Die ID des Datenpunkts.
     * @param {Object} value - Der Wert für den Datenpunkt.
     */
    async setAckFlag(id, value = {}) {
        try {
            if (id) {
                await this.setStateAsync(id, {
                    ack: true,
                    ...value,
                });
                this.log.debug(`Setze ack Flag für ${id} auf ${JSON.stringify(value)}`);
            }
        } catch (e) {
            this.log.warn(`setAckFlag: ${e.message}`);
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Schliesst den Adapter und bereinigt Ressourcen.
     * @param {() => void} callback - Der Callback, der nach der Bereinigung aufgerufen wird.
     */
    async onUnload(callback) {
        try {
            this.log.debug("Adapter wird beendet. Bereinige Ressourcen...");
            this.updateInterval && this.clearInterval(this.updateInterval);
            this.qualityInterval && this.clearInterval(this.qualityInterval);
            this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
            this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
            this.sleepTimer && this.clearTimeout(this.sleepTimer);
            this.updateThinq1Interval && this.clearInterval(this.updateThinq1Interval);
            this.updateThinq1SingleInterval && this.clearInterval(this.updateThinq1SingleInterval);
            for (const dev in this.workIds) {
                if (this.modelInfos[dev] && this.modelInfos[dev]["thinq2"] === "thinq1") {
                    const data = {
                        platformType: "thinq1",
                        deviceId: dev,
                    };
                    await this.stopMonitor(data);
                }
            }
            callback();
        } catch (e) {
            this.log.error(`Fehler beim Beenden des Adapters: ${e.message}`);
            callback();
        }
    }

    /**
     * Bereinigt Qualitätsdaten.
     */
    async cleanupQuality() {
        const quality = {
            0: "0x00 - good",
            1: "0x01 - general problem",
            2: "0x02 - no connection problem",
            16: "0x10 - substitute value from controller",
            17: "0x11 - general problem by instance",
            18: "0x12 - instance not connected",
            32: "0x20 - substitute initial value",
            64: "0x40 - substitute value from device or instance",
            65: "0x41 - general problem by device",
            66: "0x42 - device not connected",
            68: "0x44 - device reports error",
            128: "0x80 - substitute value from sensor",
            129: "0x81 - general problem by sensor",
            130: "0x82 - sensor not connected",
            132: "0x84 - sensor reports error",
        };
        this.log.debug("Start check quality");
        try {
            const devices = await this.getDevicesAsync();
            for (const device of devices) {
                const deviceId = device._id.split(".").pop();
                const all_dp = await this.getObjectListAsync({
                    startkey: `${this.namespace}.${deviceId}.`,
                    endkey: `${this.namespace}.${deviceId}.\u9999`,
                });
                const dp_array = [];
                if (all_dp && all_dp.rows) {
                    let role;
                    for (const dp of all_dp.rows) {
                        if (dp.value.type === "state") {
                            const states = await this.getStateAsync(dp.id);
                            if (states && states.q != null && states.q != 0) {
                                this.log.debug(`Datapoint: ${dp.id} - ${JSON.stringify(states)}`);
                                if (quality[states.q]) {
                                    const isfind = dp_array.find((mes) => mes.message === quality[states.q]);
                                    if (isfind) {
                                        this.log.debug(`Found: ${JSON.stringify(isfind)}`);
                                        ++isfind.counter;
                                        isfind.dp[isfind.counter] = dp.id;
                                    } else {
                                        this.log.debug(`Not Found`);
                                        const new_array = {
                                            message: quality[states.q],
                                            quality: states.q,
                                            counter: 1,
                                            dp: { 1: dp.id },
                                        };
                                        dp_array.push(new_array);
                                    }
                                    if (
                                        dp.value &&
                                        dp.value.common &&
                                        dp.value.common.role &&
                                        dp.value.common.role.toString().match(/button/gi)
                                    ) {
                                        role = { val: false };
                                    } else {
                                        role = null;
                                    }
                                    if (quality[states.q] === "0x20 - substitute initial value") {
                                        await this.setStateAsync(`${dp.id}`, {
                                            ack: true,
                                            ...role,
                                        });
                                        this.log.debug(`Setze Qualität für ${dp.id} auf ${JSON.stringify(role)}`);
                                    }
                                } else {
                                    this.log.debug(`Missing quality: ${states.q}`);
                                }
                            }
                        }
                    }
                }
                await this.setStateAsync(`${deviceId}.quality`, {
                    val:
                        Object.keys(dp_array).length > 0
                            ? JSON.stringify(dp_array)
                            : JSON.stringify({ message: "No Message" }),
                    ack: true,
                });
                this.log.debug(`Setze Qualität für ${deviceId}: ${JSON.stringify(dp_array)}`);
            }
        } catch (e) {
            this.log.info(`cleanupQuality: ${e.message}`);
        }
    }

    /**
     * Bereinigt alte Versionen des Adapters.
     */
    async cleanOldVersion() {
        const cleanOldVersion = await this.getObjectAsync("oldVersionCleaned");

        if (!cleanOldVersion) {
            try {
                const devices = await this.getDevicesAsync();
                for (const element of devices) {
                    const id = element["_id"].split(".").pop();
                    await this.delObjectAsync(`${id}`, { recursive: true });
                    this.log.debug(`Gelöscht: ${id}`);
                }
            } catch (e) {
                this.log.info(`Cannot delete a folder: ${e.message}`);
            }
            await this.setObjectNotExistsAsync("oldVersionCleaned", {
                type: "state",
                common: {
                    name: {
                        en: "Version check",
                        de: "Versionskontrolle",
                        ru: "Проверка версии",
                        pt: "Verificação da versão",
                        nl: "Versie controle",
                        fr: "Vérification de la version",
                        it: "Controllo della versione",
                        es: "Verificación de la versión",
                        pl: "Kontrola",
                        uk: "Перевірка версій",
                        "zh-cn": "检查",
                    },
                    type: "string",
                    role: "meta.version",
                    write: false,
                    read: true,
                },
                native: {},
            });
            this.log.info("Done with cleaning");
        }
        if (this.version == null) this.version = "1.0.2";
        await this.setStateAsync("oldVersionCleaned", this.version, true);
    }
}

// Exportiere den Konstruktor im kompakten Modus
if (require.main !== module) {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new LgThinq(options);
} else {
    // Starte die Instanz direkt
    new LgThinq();
}
