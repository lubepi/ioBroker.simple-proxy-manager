/* global before, it */

const path = require("path");
const assert = require("node:assert/strict");
const { tests } = require("@iobroker/testing");

function waitForAdapterFailure(harness, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timeoutHandle);
      harness.removeListener("failed", onFailed);
    };

    const onFailed = (codeOrSignal) => {
      cleanup();
      resolve(codeOrSignal);
    };

    const timeoutHandle = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out while waiting for adapter failure"));
    }, timeoutMs);

    harness.on("failed", onFailed);

    void harness.startAdapter().catch((err) => {
      cleanup();
      reject(err);
    });
  });
}

tests.integration(path.join(__dirname, "..", ".."), {
  defineAdditionalTests({ suite }) {
    suite("Fail-fast on invalid CIDR configuration", (getHarness) => {
      let harness;

      before(() => {
        harness = getHarness();
      });

      it("terminates cleanly when CIDR contains multiple '/' separators", async function () {
        this.timeout(30000);

        await harness.changeAdapterConfig(harness.adapterName, {
          native: {
            httpsPort: 18443,
            httpPort: 18080,
            backends: [
              {
                enabled: true,
                hostname: "invalid-cidr.local",
                target: "http://127.0.0.1:3000",
                allowedNetworks: "10.0.0.0/24/1",
                changeOrigin: false,
                certificate: "",
              },
            ],
          },
        });

        const stopInfo = await waitForAdapterFailure(harness);
        assert.notEqual(stopInfo, undefined);
      });
    });

    suite("Fail-fast on malformed backend types", (getHarness) => {
      let harness;

      before(() => {
        harness = getHarness();
      });

      it("terminates cleanly when allowedNetworks is not a string", async function () {
        this.timeout(30000);

        await harness.changeAdapterConfig(harness.adapterName, {
          native: {
            httpsPort: 19443,
            httpPort: 19080,
            backends: [
              {
                enabled: true,
                hostname: "type-error.local",
                target: "http://127.0.0.1:3001",
                allowedNetworks: { invalid: true },
                changeOrigin: false,
                certificate: "",
              },
            ],
          },
        });

        const stopInfo = await waitForAdapterFailure(harness);
        assert.notEqual(stopInfo, undefined);
      });
    });
  },
});
