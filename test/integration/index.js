/* global before, it */

const fs = require('node:fs');
const path = require('path');
const assert = require('node:assert/strict');
const { tests } = require('@iobroker/testing');

function getObject(harness, id) {
    return new Promise((resolve, reject) => {
        harness.objects.getObject(id, (err, obj) => {
            if (err) {
                return reject(err);
            }
            resolve(obj);
        });
    });
}

function setObject(harness, obj) {
    return new Promise((resolve, reject) => {
        harness.objects.setObject(obj._id, obj, err => {
            if (err) {
                return reject(err);
            }
            resolve(undefined);
        });
    });
}

/**
 * Waits until the adapter has logged a message matching the given pattern.
 *
 * @param harness - The test harness with access to the adapter logs
 * @param pattern - Text that must be contained in one of the log messages
 * @param timeoutMs - Maximum time to wait
 */
async function waitForLog(harness, pattern, timeoutMs = 15000) {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
        if (harness.hasLog(pattern)) {
            return;
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for log message: ${pattern}`);
}

/**
 * Writes the ioBroker default certificate plus an ACME-style certificate collection.
 *
 * @param harness - The test harness with access to the objects DB
 * @param chainFormat - `acme5` reproduces acme-client v5 (PEM blocks without trailing newline),
 * `acme4` reproduces the old `acme` package (every PEM block ends with a newline)
 */
async function prepareCertificates(harness, chainFormat = 'acme5') {
    const fixtureDir = path.join(__dirname, 'fixtures');
    const key = fs.readFileSync(path.join(fixtureDir, 'leaf.key'), 'utf8');
    const leaf = fs.readFileSync(path.join(fixtureDir, 'leaf.crt'), 'utf8').trimEnd();
    const ca = fs.readFileSync(path.join(fixtureDir, 'ca.crt'), 'utf8').trimEnd();

    const chain = chainFormat === 'acme4' ? [`${leaf}\n`, `${ca}\n`] : [leaf, ca];

    const certsObj = await getObject(harness, 'system.certificates');
    if (!certsObj) {
        throw new Error('system.certificates object not found');
    }

    certsObj.native = certsObj.native || {};
    certsObj.native.certificates = {
        ...(certsObj.native.certificates || {}),
        defaultPrivate: key,
        defaultPublic: leaf,
    };
    certsObj.native.collections = {
        ...(certsObj.native.collections || {}),
        acme: {
            key,
            cert: leaf,
            chain,
            domains: ['acme-test.local'],
        },
    };

    await setObject(harness, certsObj);
}

/**
 * Configures a backend using the `acme` collection, starts the adapter and asserts
 * that the certificate chain was accepted by tls.createSecureContext().
 *
 * @param harness - The test harness with access to the objects DB and adapter logs
 * @param options - Chain format, ports and backend target to use
 * @param options.chainFormat - `acme5` or `acme4`
 * @param options.httpsPort - Port for the HTTPS listener
 * @param options.httpPort - Port for the HTTP listener
 * @param options.target - Backend target URL
 */
async function assertAcmeChainIsUsable(harness, options) {
    await prepareCertificates(harness, options.chainFormat);

    await harness.changeAdapterConfig(harness.adapterName, {
        native: {
            httpsPort: options.httpsPort,
            httpPort: options.httpPort,
            backends: [
                {
                    enabled: true,
                    hostname: 'acme-test.local',
                    target: options.target,
                    allowedNetworks: '',
                    changeOrigin: false,
                    certificate: 'acme',
                },
            ],
        },
    });

    try {
        await harness.startAdapterAndWait();
        // startAdapterAndWait only waits for the alive state, which is set before onReady finished.
        await waitForLog(harness, 'HTTPS reverse proxy running');

        assert.equal(
            harness.hasLog('Failed to create TLS context'),
            false,
            `Unexpected TLS context error: ${JSON.stringify(harness.getLogs('error'))}`,
        );
        assert.equal(
            harness.hasLog('HTTPS disabled for host(s)'),
            false,
            `HTTPS was disabled unexpectedly: ${JSON.stringify(harness.getLogs('error'))}`,
        );
    } finally {
        await harness.stopAdapter();
    }
}

function waitForAdapterFailure(harness, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
        const cleanup = () => {
            clearTimeout(timeoutHandle);
            harness.removeListener('failed', onFailed);
        };

        const onFailed = codeOrSignal => {
            cleanup();
            resolve(codeOrSignal);
        };

        const timeoutHandle = setTimeout(() => {
            cleanup();
            reject(new Error('Timed out while waiting for adapter failure'));
        }, timeoutMs);

        harness.on('failed', onFailed);

        void harness.startAdapter().catch(err => {
            cleanup();
            reject(err);
        });
    });
}

tests.integration(path.join(__dirname, '..', '..'), {
    defineAdditionalTests({ suite }) {
        suite('Fail-fast on invalid CIDR configuration', getHarness => {
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
                                hostname: 'invalid-cidr.local',
                                target: 'http://127.0.0.1:3000',
                                allowedNetworks: '10.0.0.0/24/1',
                                changeOrigin: false,
                                certificate: '',
                            },
                        ],
                    },
                });

                const stopInfo = await waitForAdapterFailure(harness);
                assert.notEqual(stopInfo, undefined);
            });
        });

        suite('Fail-fast on malformed backend types', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('terminates cleanly when allowedNetworks is not a string', async function () {
                this.timeout(30000);

                await harness.changeAdapterConfig(harness.adapterName, {
                    native: {
                        httpsPort: 19443,
                        httpPort: 19080,
                        backends: [
                            {
                                enabled: true,
                                hostname: 'type-error.local',
                                target: 'http://127.0.0.1:3001',
                                allowedNetworks: { invalid: true },
                                changeOrigin: false,
                                certificate: '',
                            },
                        ],
                    },
                });

                const stopInfo = await waitForAdapterFailure(harness);
                assert.notEqual(stopInfo, undefined);
            });
        });

        suite('ACME certificate chain without trailing newlines (issue #73)', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('creates the TLS context for an ACME-style collection', async function () {
                this.timeout(60000);

                await assertAcmeChainIsUsable(harness, {
                    chainFormat: 'acme5',
                    httpsPort: 21443,
                    httpPort: 21080,
                    target: 'http://127.0.0.1:3002',
                });
            });
        });

        suite('ACME certificate chain from older ACME versions (issue #73)', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('creates the TLS context for a chain with trailing newlines', async function () {
                this.timeout(60000);

                await assertAcmeChainIsUsable(harness, {
                    chainFormat: 'acme4',
                    httpsPort: 22443,
                    httpPort: 22080,
                    target: 'http://127.0.0.1:3003',
                });
            });
        });
    },
});
