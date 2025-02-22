/**
 * @author Typed By goataso
 * @version 1.1.7
 */
const ERROR_204 = 'Request rate limit exceeded. You are making more requests than allowed.'
const ERROR_400 = 'Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.'
const ERROR_403 = 'Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.'

declare module 'virustotal-api' {
    /**
     * Options for configuring the VirusTotal API.
     * @interface VirusTotalOptions
     * @property {boolean} [compressed = true] - Whether to set 'Accept-Encoding' to 'gzip,deflate' (default: true).
     * @property {number} [follow_max = 5] - The maximum number of redirects to follow (default: 5).
     * @property {boolean} [rejectUnauthorized = true] - Whether to check the SSL certificate (default: true).
     * @property {boolean} [multipart = true] - Whether to use multipart form data in requests (default: true).
     * @property {number} [timeout = 120000] - The timeout for requests in milliseconds (default: 120000).
     * @property {string} [user_agent = 'virustotal-api'] - The user agent string to use for requests (default: 'virustotal-api').
     */

    export interface VirusTotalOptions {
        compressed: boolean;
        follow_max: number;
        rejectUnauthorized: boolean;
        multipart: boolean;
        timeout: number;
        user_agent: 'virustotal-api' | string;
    };

    export type BodyData = Buffer | KeyValue | NodeJS.ReadableStream | string | null
    /**
     * @summary Virustotal API v2.0 wrapper
     * @see {@link https://developers.virustotal.com/v2.0/reference}
     * @class VirusTotal
     */
    export default class VirusTotal {
        constructor(apiKey: string, options?: VirusTotalOptions);
        /**
         * @summary returns apiKey which can be access by this._apiKey;
         * @returns { string } API Key
         */
        private readonly get apiKey(): string;

        /**
         * @summary Retrieve file scan reports
         * @param {string} resource - Resource(s) to be retrieved
         * @param {boolean} [allinfo=false] - [PRIVATE API] - Return all info
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileReport(resource: string, allinfo: boolean = false): Error<string> | Promise<BodyData>;
        /**
         * @summary Scan a file
         * @param {Buffer} fileContent - Binary content of the file
         * @param {string} [fileName='unknown'] - Provides metadata to antiviruses if specified
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public fileScan(fileContent: string, fileName: string = 'unknown'): Error<string> | Promise<BodyData>;
        /**
         * @summary [RESTRICTED API] Get a URL for uploading files larger than 32MB
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileScanUploadUrl(): Error<string> | Promise<BodyData>;
        /**
         * @summary Re-scan a file
         * @param {string} resource - Resource(s) to be retrieved
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileRescan(resource: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Download a file
         * @param {string} hash - The md5/sha1/sha256 hash of the file you want to download
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileDownload(hash: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Retrieve behaviour report
         * @param {string} hash - The md5/sha1/sha256 hash of the file whose dynamic behavioural report you want to retrieve.
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileBehaviour(hash: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Retrieve network traffic report
         * @param {string} hash - The md5/sha1/sha256 hash of the file whose network traffic dump you want to retrieve
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileNetworkTraffic(hash: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Retrieve live feed of all files submitted to VirusTotal
         * @param {string} package_ - Indicates a time window to pull reports on all items received during such window. Timestamp less than 24 hours ago, UTC.
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        async fileFeed(package_: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Retrieve file clusters
         * @param {string} date - A date for which we want to access the clustering details in YYYY-MM-DD format.
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        async fileClusters(date: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Search for files
         * @param {string} query - Search query
         * @param {string | number} [offset = -1] - The offset value returned by a previous identical query, allows you to paginate over the results.
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async fileSearch(query: string, offset: string | number = -1): Error<string> | Promise<BodyData>;
        /**
         * @summary Retrieve URL scan reports
         * @param {string} scanIdOrUrl - A URL for which you want to retrieve the most recent report. You may also specify a scan_id (sha256-timestamp as returned by the URL submission API) to access a specific report.
         * @param {boolean} [allinfo=false] - Return additional information about the file
         * @param {number} [scan=0] - This is an optional parameter that when set to "1" will automatically submit the URL for analysis if no report is found for it in VirusTotal's database. In this case the result will contain a scan_id field that can be used to query the analysis report later on.
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async urlReport(scanIdOrUrl: string, allinfo: boolean = false, scan: number = 0): Error<string> | Promise<BodyData>;
        /**
         * @summary Scan an URL
         * @param {string} url - The URL that should be scanned
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async urlScan(url: string): Error<string> | Promise<BodyData>;
        /**
         * @summary [PRIVATE API] Retrieve live feed of all URLs submitted to VirusTotal
         * @param {string} package_ - Indicates a time window to pull reports on all items received during such window
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async urlFeed(package_: string): Error<string> | Promise<BodyData>;
        /**
         * @summary Retrieves a domain report
         * @param {string} domain - Domain name
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async domainReport(domain: string): Error<string> | Promise<BodyData>;
        /**
         * @summary Retrieve an IP address report
         * @param {string} ip - IP address
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async ipAddressReport(ip: string): Error<string> | Promise<BodyData>;
        /**
         * @summary Get comments for a file or URL
         * @param {string} resource - Either an md5/sha1/sha256 hash of the file or the URL itself you want to retrieve.
         * @param {string} [before=null] - A datetime token that allows you to iterate over all comments on a specific item whenever it has been commented on more than 25 times.
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async commentsGet(resource: string, before: string = null): Error<string> | Promise<BodyData>;
        /**
         * @summary Post comment for a file or URL
         * @param {string} resource - Either an md5/sha1/sha256 hash of the file you want to review or the URL itself that you want to comment on
         * @param {string} comment - The comment's text
         * @returns {Error<string> | Promise<BodyData>} - Response object
         * @memberof VirusTotal
         */
        public async commentsPut(resource: string, comment: string): Error<string> | Promise<BodyData>;
        /**
         * Check response status code
         * @private
         * @param {Object} res - Response object
         * @returns {Error<string> | null} - Returns error object in case of error
         * @memberof VirusTotal
         */
        private _checkResponse (res) : Error<string> | null;
    }
}
