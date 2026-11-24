<?php declare(strict_types=1);

namespace LukasHron\SentinelProbe\Rules\Content;

/**
 * Known vulnerable versions of popular frontend libraries.
 *
 * url:    alternation of names as they appear in paths, followed by @, - or / and the version
 *         (jquery-3.4.1.min.js, /jquery@3.4.1/, /ajax/libs/jquery/3.4.1/)
 * banner: pattern of the license comment, the first group is the version
 * eol:    reason the library is no longer maintained, null when it is maintained
 * vulns:  [min (inclusive, null = any), max (exclusive), CVE list, summary]
 */
final class VulnerableLibraries
{
    /**
     * @return array<string, array{url: string, banner: ?string, eol: ?string, vulns: list<array{?string, string, string, string}>}>
     */
    public static function all(): array
    {
        return [
            'jQuery' => [
                'url' => 'jquery',
                'banner' => '~jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)~',
                'eol' => null,
                'vulns' => [
                    [null, '1.9.0', 'CVE-2012-6708', 'XSS in selector'],
                    [null, '3.0.0', 'CVE-2015-9251', 'cross-domain Ajax executes scripts'],
                    [null, '3.4.0', 'CVE-2019-11358', 'prototype pollution in extend()'],
                    [null, '3.5.0', 'CVE-2020-11022, CVE-2020-11023', 'XSS in HTML manipulation'],
                ],
            ],
            'jQuery UI' => [
                'url' => 'jquery-ui|jqueryui',
                'banner' => '~jQuery UI (?:- v|[A-Z][\w ]*? )(\d+\.\d+\.\d+)~',
                'eol' => null,
                'vulns' => [
                    [null, '1.12.0', 'CVE-2016-7103', 'XSS in dialog closeText'],
                    [null, '1.13.0', 'CVE-2021-41182, CVE-2021-41183, CVE-2021-41184', 'XSS in datepicker and position()'],
                    [null, '1.13.2', 'CVE-2022-31160', 'XSS in checkboxradio label'],
                ],
            ],
            'Bootstrap' => [
                'url' => 'bootstrap',
                'banner' => '~Bootstrap v(\d+\.\d+\.\d+)~',
                'eol' => null,
                'vulns' => [
                    [null, '3.4.0', 'CVE-2018-14040, CVE-2018-14041, CVE-2018-14042, CVE-2018-20676, CVE-2018-20677', 'XSS in data attributes'],
                    ['3.0.0', '3.4.1', 'CVE-2019-8331', 'XSS in tooltip/popover data-template'],
                    ['4.0.0', '4.3.1', 'CVE-2019-8331', 'XSS in tooltip/popover data-template'],
                    ['3.0.0', '4.0.0', 'CVE-2024-6484', 'XSS in carousel (Bootstrap 3 is end-of-life, no fix)'],
                    ['4.0.0', '5.0.0', 'CVE-2024-6531', 'XSS in carousel (Bootstrap 4 is end-of-life, no fix)'],
                ],
            ],
            'AngularJS' => [
                'url' => 'angular\.js|angularjs|angular',
                'banner' => '~AngularJS v(1\.\d+\.\d+)~',
                'eol' => 'AngularJS reached end of life in December 2021, ReDoS issues CVE-2022-25844, CVE-2023-26116, CVE-2023-26117, CVE-2023-26118 stay unfixed',
                'vulns' => [
                    [null, '1.7.9', 'CVE-2019-10768', 'prototype pollution in merge()'],
                    [null, '1.8.0', 'CVE-2020-7676', 'XSS in <option> elements'],
                ],
            ],
            'Lodash' => [
                'url' => 'lodash\.js|lodash',
                'banner' => null,
                'eol' => null,
                'vulns' => [
                    [null, '4.17.12', 'CVE-2019-10744', 'prototype pollution in defaultsDeep()'],
                    [null, '4.17.19', 'CVE-2020-8203', 'prototype pollution in zipObjectDeep()'],
                    [null, '4.17.21', 'CVE-2021-23337, CVE-2020-28500', 'command injection in template(), ReDoS'],
                ],
            ],
            'Moment' => [
                'url' => 'moment\.js|moment',
                'banner' => '~moment\.js\s*(?://!|\*)?\s*version\s*:\s*(\d+\.\d+\.\d+)~i',
                'eol' => 'Moment is in maintenance mode since 2020, prefer Luxon, date-fns or the Temporal API',
                'vulns' => [
                    [null, '2.29.4', 'CVE-2022-31129', 'ReDoS in RFC 2822 parsing'],
                ],
            ],
            'Handlebars' => [
                'url' => 'handlebars\.js|handlebars',
                'banner' => '~handlebars v(\d+\.\d+\.\d+)~i',
                'eol' => null,
                'vulns' => [
                    [null, '4.5.3', 'CVE-2019-19919', 'prototype pollution'],
                    [null, '4.7.7', 'CVE-2021-23369, CVE-2021-23383', 'code execution when compiling untrusted templates'],
                ],
            ],
            'DOMPurify' => [
                'url' => 'dompurify',
                'banner' => '~DOMPurify (\d+\.\d+\.\d+)~',
                'eol' => null,
                'vulns' => [
                    [null, '2.0.17', 'CVE-2020-26870', 'mutation XSS'],
                    [null, '2.5.4', 'CVE-2024-45801', 'sanitizer bypass via nesting depth'],
                    ['3.0.0', '3.1.3', 'CVE-2024-45801', 'sanitizer bypass via nesting depth'],
                    [null, '3.2.4', 'CVE-2025-26791', 'mutation XSS with SAFE_FOR_TEMPLATES'],
                ],
            ],
        ];
    }
}
