/*
Copyright (C) 2017 André Jaenisch

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

'use strict'

const childProcess = require('child_process')
const rssParser = require('rss-parser')

const snykFeedUrl = 'https://snyk.io/vuln/feed.xml?type=npm'

const aTagRegExp = /<a href="([-.:/\w\n]+)">/g
const codeTagRegExp = /<\/?(a|code|em|p|strong)>/g
// [\s\S] matches anything including newlines
const affectedPackageRegExp = /[\s\S]*<strong>Affects:\s*([-.\w]+)<\/strong>/
const detailsRegExp = /[\s\S]*<h2 id="overview">Overview<\/h2>\n<p>([\s\S]+)<\/p>\n<h2 id="remediation">/
const referenceRegExp = /[\s\S]*<h2 id="references">References<\/h2>\n<ul>([\s\S]*)<\/ul>/
const remediationRegExp = /[\s\S]*<h2 id="remediation">Remediation<\/h2>\n<p>([\s\S]+)<\/p>/
const severityRegExp = /[\s\S]*<strong>Severity:\s*(\w+)<\/strong>/

const getAffectedPackage = (snippet) => {
    let match = affectedPackageRegExp.exec(snippet)
    return match === null ? match : match[1]
}

const getDetails = (snippet) => {
    let match = detailsRegExp.exec(snippet)
    if (match === null) {
        return match
    }

    return match[1].replace(codeTagRegExp, '').replace(aTagRegExp, '')
}

const getReference = (snippet) => {
    let match = referenceRegExp.exec(snippet)
    if (match === null) {
        return match
    }
    let references = match[1].replace(codeTagRegExp, '')
    return references.split('</li>').map((item) => {
        let url = aTagRegExp.exec(references)
        let text = item.replace(aTagRegExp, '').replace('\n<li>', '')
        return {url: url === null ? null : url[1], text: text}
    }).filter((item) => {
        return item.text.trim().length > 0
    })
}

const getRemediation = (snippet) => {
    let match = remediationRegExp.exec(snippet)
    return match === null ? match : match[1].replace(codeTagRegExp, '')
}

const getSeverity = (snippet) => {
    let match = severityRegExp.exec(snippet)
    return match === null ? match : match[1]
}

const parseFeed = (feedItem) => {
    let content = feedItem.content
    // console.log('DEBUG', feedItem.contentSnippet)
    return {
        affectedPackage: getAffectedPackage(content),
        details: getDetails(content),
        link: feedItem.link,
        reference: getReference(content),
        remediation: getRemediation(content),
        severity: getSeverity(content),
        snippet: feedItem.contentSnippet
    }
}

const onUrlParsed = (error, parsed) => {
    if (error) {
        console.error(error)
        return
    }

    parsed.feed.entries.forEach((entry) => {
        console.log(parseFeed(entry))
    })
}

const parse = () => {
    rssParser.parseURL(snykFeedUrl, onUrlParsed)
}

const onExec = (exitCode, stdout, stderr) => {
    parse()
    // exitCode lists the number of outdated libraries found
    if (exitCode === null) {
        // Nothing is outdated
        return
    }
    let libs = JSON.parse(stdout)
    console.log(libs)
}

childProcess.exec('npm outdated --json', onExec)
