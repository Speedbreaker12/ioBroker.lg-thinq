
"use strict";

const utils = require("@iobroker/adapter-core");
const constants = require("./lib/constants");

class LgThinq extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "lg-thinq",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    async onReady() {
        this.app_agent = constants.APP_AGENT[Math.floor(Math.random() * constants.APP_AGENT.length)];
        this.app_device = constants.APP_DEVICE[Math.floor(Math.random() * constants.APP_DEVICE.length)];
        await this.setState("info.connection", false, true);
        await this.cleanOldVersion();

        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        if (this.config.interval_thinq1 < 0 || this.config.interval_thinq1 > 1440) {
            this.log.info("Set thinq1 interval to 30 seconds");
            this.config.interval_thinq1 = 30;
        }

        this.refreshCounter = {
            "interval.active": null,
            "interval.inactive": null,
            "interval.status_devices": null
        };

        const data = await this.getForeignObjectAsync("system.config");
        if (data && data.common && data.common.language) {
            this.lang = data.common.language === this.lang ? this.lang : "en";
        }
        this.log.debug(this.lang);

        this.defaultHeaders = {
            "x-api-key": constants.API_KEY,
            "x-client-id": constants.API_CLIENT_ID,
            "x-thinq-app-ver": "3.5.1700",
            "x-thinq-app-type": "NUTS",
            "x-thinq-app-level": "PRD",
            "x-thinq-app-os": "ANDROID",
            "x-thinq-app-logintype": "LGE",
            "x-service-code": "SVC202",
            "x-country-code": this.config.country,
            "x-language-code": this.config.language,
            "x-service-phase": "OP",
            "x-origin": "app-native",
            "x-model-name": "samsung / SM-N950N",
            "x-os-version": "7.1.2",
            "x-app-version": "3.5.1721",
            "x-message-id": this.random_string(22),
        };

        try {
            const gatewayResponse = await this.requestClient.get(constants.GATEWAY_URL, { headers: this.defaultHeaders });
            const response = gatewayResponse?.data?.result;

            if (!response || !response.countryCode) {
                this.log.error("Invalid gateway response: Missing countryCode");
                return;
            }

            this.gateway = response;
            this.log.debug(JSON.stringify(this.gateway));

            this.lgeapi_url = `https://${this.gateway.countryCode.toLowerCase()}.lgeapi.com/`;
        } catch (error) {
            this.log.error("Error fetching gateway information: " + error.message);
            return;
        }

        try {
            this.session = await this.login(this.config.user, this.config.password);
            if (!this.session) {
                this.log.error("Session creation failed. Please check your login credentials.");
                return;
            }
        } catch (error) {
            this.log.error("Login error: " + error.message);
            return;
        }

        this.log.info("Adapter successfully initialized!");
    }
}

// Export the class as module
module.exports = (options) => new LgThinq(options);
