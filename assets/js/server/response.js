import { marshal } from '../utils';
export const json = (data, headers = {}, statusCode = 200) => {
    return new Response(marshal(data), {
        status: statusCode,
        headers: {
            ...headers,
            'content-type': 'application/json;charset=UTF-8',
        },
    });
};
//# sourceMappingURL=response.js.map