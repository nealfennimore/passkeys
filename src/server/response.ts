export const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Allow-Credentials': 'true',
};

export const json = (
    data: object,
    headers: Record<string, string> = {},
    statusCode = 200
) => {
    return new Response(JSON.stringify(data), {
        status: statusCode,
        headers: {
            ...headers,
            ...corsHeaders,
            'content-type': 'application/json;charset=UTF-8',
        },
    });
};
