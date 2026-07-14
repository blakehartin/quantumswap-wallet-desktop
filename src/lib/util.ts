export function isNetworkError(error: { message: string }) {
    const err = error.message.toLowerCase();
    return (err.includes("failed to fetch") || err.includes("timeout") || err.includes("network request failed"));
}

export function isLargeNumber(val: string) {
    const rgx = /^([0-9]+([.][0-9]*)?|[.][0-9]+)$/;
    return Boolean(val.match(rgx));
}

export function isValidDate(dateStr: string) {
    return !isNaN(new Date(dateStr) as any);
}

export function isHex(num: string) {
    return Boolean(num.match(/^0x[0-9a-f]+$/i))
}

export function htmlEncode(rawStr: string) {
    return rawStr.replace(/[\u00A0-\u9999<>&]/g, i => '&#' + i.charCodeAt(0) + ';')
}
