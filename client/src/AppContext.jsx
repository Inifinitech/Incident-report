import { createContext, useEffect, useState } from "react";

export const AppContext = createContext()
const AppContextProvider = (props) => {
    const [userData, setUserData] = useState()
    const [incidents, setIncidents] = useState([])
    const [filter, setFilter] = useState('all')
    const [search, setSearch] = useState('')

    const user_id = localStorage.getItem('user_id')
    useEffect(()=> {
        fetch (`https://incident-report-98rf.onrender.com/user/${user_id}`)
        .then((resp) => resp.json())
        .then((data) => setUserData(data))
    }, [user_id])

    const value = {
        userData, setUserData
    }

    useEffect(() => {
        fetch('https://incident-report-98rf.onrender.com/incidents')
        .then((resp) => resp.json())
        .then((data) => setIncidents(data))
        .catch((error) => console.error('Error fetching incidents', error))
    }, []);


    return (
        <AppContext.Provider value={{value, incidents, setIncidents, filter, setFilter, search, setSearch}}>
            {props.children}
        </AppContext.Provider>
    )
}

export default AppContextProvider;
