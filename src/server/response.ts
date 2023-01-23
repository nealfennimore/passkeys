
import { marshal } from '../utils';

export const json = (data: object, headers: Record<string, string> = {}, statusCode = 200 ) => {
    return new Response(marshal(data), {
        status: statusCode,
        headers: {
            ...headers,
            'content-type': 'application/json;charset=UTF-8',
        }
    })    
}