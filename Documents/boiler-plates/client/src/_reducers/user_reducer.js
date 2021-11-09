import {
    LOGIN_USER,
    REGISTER_USER,
    AUTH_USER
} from '../_actions/types';

// eslint-disable-next-line import/no-anonymous-default-export
export default function (state = {}, action) {
    switch (action.type) {
        case LOGIN_USER:
            return { ...state, loginSuccess: action.payload }
            // eslint-disable-next-line no-unreachable
            break;
        case REGISTER_USER:
            return { ...state, register: action.payload }
            // eslint-disable-next-line no-unreachable
            break;
        case AUTH_USER:
            return { ...state, userData: action.payload }
            // eslint-disable-next-line no-unreachable
            break;
        default:
            return state;
    }
}