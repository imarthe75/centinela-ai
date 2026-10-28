import { createContext, useContext } from 'react'

// Everything the Dashboard shell owns (state, setters, handlers) is published here so each view/modal can live in its own file.
export const DashboardContext = createContext(null)
export const useDashboard = () => useContext(DashboardContext)
