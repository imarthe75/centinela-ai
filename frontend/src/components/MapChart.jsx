import React from "react"
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker
} from "react-simple-maps"

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

const MapChart = ({ markers = [] }) => {
  return (
    <ComposableMap
      projectionConfig={{
        // Centered on Mexico
        rotate: [102, -23.5, 0],
        scale: 1200
      }}
      style={{
        width: "100%",
        height: "auto",
      }}
    >
      <Geographies geography={geoUrl}>
        {({ geographies }) =>
          geographies.map((geo) => (
            <Geography
              key={geo.rsmKey}
              geography={geo}
              fill="#1E293B"
              stroke="#334155"
              strokeWidth={0.5}
              style={{
                default: { outline: "none" },
                hover: { fill: "#334155", outline: "none" },
                pressed: { fill: "#0F172A", outline: "none" },
              }}
            />
          ))
        }
      </Geographies>
      {markers.map(({ asset_name, location_lat, location_lon, criticality }) => {
        // Criticality colors
        const color = criticality === "CRITICAL" || criticality === "Critical" ? "#EF4444" : 
                      criticality === "HIGH" || criticality === "High" ? "#F97316" : 
                      criticality === "MEDIUM" || criticality === "Medium" ? "#EAB308" : "#22C55E";
        
        return (
          <Marker key={asset_name} coordinates={[parseFloat(location_lon), parseFloat(location_lat)]}>
            <circle r={6} fill={color} stroke="#fff" strokeWidth={1.5} className="animate-pulse" />
            <text
              textAnchor="middle"
              y={-12}
              style={{ fontFamily: "Open Sans", fill: "#94A3B8", fontSize: "10px", fontWeight: "bold", pointerEvents: "none" }}
            >
              {asset_name}
            </text>
          </Marker>
        );
      })}
    </ComposableMap>
  )
}

export default MapChart
