import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import {
  AppBar,
  Autocomplete,
  CircularProgress,
  Icon,
  LinearProgress,
  Snackbar,
  Stack,
  Table,
  TableBody,
  TableCell,
  tableCellClasses,
  TableHead,
  TableRow,
  TextField,
} from "@mui/material";
import MuiAlert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import CssBaseline from "@mui/material/CssBaseline";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
import Grid from "@mui/material/Grid";
import IconButton from "@mui/material/IconButton";
import Paper from "@mui/material/Paper";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import { createTheme, styled, ThemeProvider } from "@mui/material/styles";
import * as React from "react";
import { Chart } from "react-google-charts";
import { Link } from "react-router-dom";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useEdgesState,
  useNodesState,
} from "reactflow";
import ParticleLinksWhite from "./ParticleLinksWhite";
import httpClient from "./httpClient";

import "reactflow/dist/style.css";
import "./overview.css";

const minimapStyle = {
  height: 120,
};

const mdTheme = createTheme();

const StyledTableCell = styled(TableCell)(({ theme }) => ({
  [`&.${tableCellClasses.head}`]: {
    backgroundColor: theme.palette.common.black,
    color: theme.palette.common.white,
  },
  [`&.${tableCellClasses.body}`]: {
    fontSize: 14,
  },
}));

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  "&:nth-of-type(odd)": {
    backgroundColor: theme.palette.action.hover,
  },
  // hide last border
  "&:last-child td, &:last-child th": {
    border: 0,
  },
}));

const Alert = React.forwardRef(function Alert (props, ref) {
  return <MuiAlert elevation={6} ref={ref} variant="filled" {...props} />;
});

function LinearProgressWithLabel (props) {
  return (
    <Box sx={{ display: "flex", alignItems: "center" }}>
      <Box sx={{ width: "100%", mr: 1 }}>
        <LinearProgress variant="determinate" {...props} />
      </Box>
      <Box sx={{ minWidth: 35 }}>
        <Typography variant="body2" color="text.secondary">{`${Math.round(
          props.value,
        )}%`}</Typography>
      </Box>
    </Box>
  );
}

function App () {
  const [file, setFile] = React.useState(null);
  const [fileLabel, setfileLabel] = React.useState("Upload File");

  const [vendorPie, setVendorPie] = React.useState([]);
  const [protocolPie, setProtocolPie] = React.useState([]);
  const [assetData, setAssetData] = React.useState([]);
  const [cveData, setcveData] = React.useState([]);

  const [vendorlist, setvendorlist] = React.useState([]);
  const [maclist, setmaclist] = React.useState([]);
  const [iplist, setiplist] = React.useState([]);
  const [protocollist, setprotocollist] = React.useState([]);

  const [openGraph, setOpenGraph] = React.useState(true);

  const handleClickOpenGraph = () => {
    setOpenGraph(true);
  };

  const handleCloseGraph = () => {
    setOpenGraph(false);
  };

  const [openLoading, setOpenLoading] = React.useState(false);
  const [spinnerloading, setspinnerloading] = React.useState(false);

  const getCountByDeviceType = (deviceType) => {
    return assetData.filter((item) => item.device_type === deviceType).length;
  };

  const [itCount, setitCount] = React.useState();
  const [otCount, setotCount] = React.useState();

  const [progress, setProgress] = React.useState(10);

  const [openDiagram, setOpenDiagram] = React.useState(false);

  const [openAlert, setOpenAlert] = React.useState(false);

  const handleClickAlert = () => {
    setOpenAlert(true);
  };

  const handleCloseAlert = (event, reason) => {
    if (reason === "clickaway") {
      return;
    }

    setOpenAlert(false);
  };

  const handleOpenLoading = () => {
    setOpenLoading(true);

    const timer = setInterval(() => {
      setProgress((prevProgress) => {
          if (prevProgress >= 100) {
            clearInterval(timer);
            handleCloseLoading();
            return 10;
          } else {
            return prevProgress + 10;
          }
        },
      );
    }, 800);

    return () => {
      clearInterval(timer);
    };
  };

  const handleCloseLoading = () => {
    setOpenLoading(false);
  };

  const handleOpenDiagram = async () => {
    const params = new FormData();
    params.append("pcap-file", file);
    let response = await httpClient.post("/graph", params);
    if (response.status === 200) {
      console.log({ data: response.data });
      // setNodes(response.data["nodes"]);
      // setEdges(response.data["edges"]);

      setOpenDiagram(true);
    } else {
      alert("Error uploading file");
    }
  };

  const handleCloseDiagram = () => {
    setOpenDiagram(false);
  };

  const [openCVETable, setOpenCVETable] = React.useState(false);

  const handleClickOpenCVETable = () => {
    setOpenCVETable(true);
  };

  const handleCloseCVETable = () => {
    setOpenCVETable(false);
  };

  const handleCVETable = async (e) => {
    console.log(e);

    let response = await httpClient.get("/cve/" + e, {
      headers: {
        "ngrok-skip-browser-warning": "69420",
      },
    });

    if (response.status === 200) {
      console.log(response.data);
      console.log(response.data[0].cve.CVE_data_meta.ID);
      console.log(response.data[0].cve.description.description_data[0].value);
      console.log(response.data[0].impact.baseMetricV3.cvssV3.baseScore);
      setcveData(response.data);
      handleClickOpenCVETable();
    } else {
      alert("Error uploading file");
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    setFile(file);
    setfileLabel(file.name);
    setspinnerloading(true);

    const data = new FormData();
    data.append("data", file);

    let response = await httpClient.post("/analyze", data);

    if (response.status === 200) {
      // handleClickAlert()
      setspinnerloading(false);

      console.log(response.data);
      console.log(response.data["connections"]);
      setVendorPie(response.data["vendor_plots"]);
      setProtocolPie(response.data["protocol_plots"]);
      setAssetData(response.data["connections"]);
      setvendorlist(
        Array.from(
          new Set(
            response.data["connections"].map((item) => item.Vendor)),
        ).map((vendor) => ({ label: vendor })),
      );
      setmaclist(
        Array.from(
          new Set(
            response.data["connections"].map((item) => item.MAC)),
        ).map((vendor) => ({ label: vendor })),
      );
      setiplist(
        Array.from(
          new Set(response.data["connections"].map((item) => item.IP)),
        ).map((vendor) => ({ label: vendor })),
      );
      setprotocollist(
        Array.from(
          new Set(response.data["connections"].map((item) => item.Protocol)),
        ).map((vendor) => ({ label: vendor })),
      );
      setitCount(response.data["connections"].filter(
        (item) => item.device_type === "IT").length);
      setotCount(response.data["connections"].filter(
        (item) => item.device_type === "OT").length);

      handleCloseGraph();
      // setAssetData(response.data['connections'])
    } else {
      setspinnerloading(false);

      alert("Error uploading file");
      setfileLabel("");
    }
  };

  const initialNodes = [
    { id: "1", position: { x: 0, y: 0 }, data: { label: "127.0.0.1" } },
    { id: "2", position: { x: 0, y: 100 }, data: { label: "127.0.0.2" } },
    { id: "3", position: { x: 200, y: 100 }, data: { label: "127.0.0.3" } },
  ];
  const initialEdges = [
    { id: "e1-2", source: "1", target: "2" },
    { id: "e2-3", source: "2", target: "3" },
  ];

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);

  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const optionsVendor = {
    title: "Vendor Details",
    pieHole: 0.4,
    is3D: false,
    legend: { position: "bottom", alignment: "start" },
  };

  const optionsProtocol = {
    title: "Protocol Details",
    pieHole: 0.4,
    is3D: false,
    legend: { position: "bottom", alignment: "start" },
  };
  const svgIcon = (
    <Icon>
      <img alt="edit" src="network.png" style={{ width: "10%" }}/>
    </Icon>
  );

  return (
    <>
      <ParticleLinksWhite/>

      <ThemeProvider theme={mdTheme}>
        <Box sx={{ display: "flex", background: "#e8d3f5", opacity: "1" }}>
          <CssBaseline/>
          <AppBar position="absolute"
                  sx={{ background: "#7607ba", height: "8%" }}>
            <Toolbar
              sx={{
                pr: "50%", // keep right padding when drawer closed
              }}
            >
              <Typography component="h1" variant="h4" color="inherit" noWrap
                          sx={{ flexGrow: 0.5 }}>
                Dashboard
              </Typography>

              <Typography component="h1" variant="h4" color="inherit" noWrap
                          sx={{ flexGrow: -1 }}>
                <Button
                  size="large"
                  variant="contained"
                  sx={{ color: "white" }}
                  component={Link}
                  to="/kibana"
                >
                  Log Analysis
                </Button>
              </Typography>

              {/* <Typography
              component="h1"
              variant="h6"
              color="inherit"
              noWrap
              sx={{ flexGrow: 1 }}
            >
              <Button

        variant="outlined"
        sx={{color: 'white'}}
        component={Link} to="/"

      >
      Logout
        </Button>
            </Typography> */}
            </Toolbar>
          </AppBar>

          <Box
            component="main"
            sx={{
              flexGrow: 1,
              height: "100vh",
              overflow: "auto",
            }}
          >
            <Toolbar/>

            {!openGraph && (
              <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
                <Grid container spacing={3}>
                  <Grid item xs={6}>
                    <Paper
                      elevation={6}
                      sx={{
                        p: 1,
                        display: "flex",
                        flexDirection: "column",
                      }}
                    >
                      <Stack direction={"row"} alignItems="center">
                        <Chart
                          chartType="PieChart"
                          data={vendorPie}
                          options={optionsVendor}
                          width={"43vh"}
                          height={"47.5vh"}
                        />
                        <Chart
                          chartType="PieChart"
                          data={protocolPie}
                          options={optionsProtocol}
                          width={"38vh"}
                          height={"47.5vh"}
                        />
                      </Stack>
                    </Paper>
                  </Grid>

                  <Grid item xs={6}>
                    <Grid container direction={"column"} spacing={3}>
                      <Grid item xs={6}>
                        <Grid container direction={"row"} spacing={3}>
                          <Grid item xs={6}>
                            <Grid container direction={"row"} spacing={3}>
                              <Grid item xs={6}>
                                <Paper
                                  elevation={6}
                                  sx={{
                                    p: 2,
                                    display: "flex",
                                    flexDirection: "column",
                                    height: 160,
                                  }}
                                >
                                  <Typography
                                    component="span"
                                    variant="h5"
                                    sx={{ color: "black", pl: 3.7 }}
                                  >
                                    Assets
                                  </Typography>
                                  <Typography
                                    component="span"
                                    variant="h4"
                                    sx={{ color: "black", pt: 0, pl: 7 }}
                                  >
                                    {assetData.length}
                                  </Typography>
                                  <hr
                                    style={{
                                      padding: "0",
                                      margin: "0.2rem",
                                      border: "1px solid black",
                                    }}
                                  />
                                  <Stack
                                    direction={"row"}
                                    // justifyContent="space-evenly"
                                    alignItems="center"
                                    sx={{ mt: 0, width: "45%", mr: "10px" }}
                                    spacing={0}
                                  >
                                    <Stack
                                      direction={"column"}
                                      // justifyContent="space-evenly"
                                      alignItems="center"
                                      sx={{ mt: 0 }}
                                      spacing={0}
                                    >
                                      <Typography
                                        component="span"
                                        variant="h5"
                                        sx={{
                                          color: "black",
                                          pl: 3.5,
                                          fontSize: "1.25rem",
                                        }}
                                      >
                                        IT
                                      </Typography>
                                      <Typography
                                        component="span"
                                        variant="h4"
                                        sx={{
                                          color: "black",
                                          pl: 4,
                                          fontSize: "1.25rem",
                                        }}
                                      >
                                        {itCount}
                                      </Typography>
                                    </Stack>
                                    <Stack
                                      direction={"column"}
                                      // justifyContent="space-evenly"
                                      alignItems="center"
                                      sx={{ mt: 0 }}
                                      spacing={0}
                                    >
                                      <Typography
                                        component="span"
                                        variant="h5"
                                        sx={{
                                          color: "black",
                                          pl: 4,
                                          fontSize: "1.25rem",
                                        }}
                                      >
                                        OT
                                      </Typography>
                                      <Typography
                                        component="span"
                                        variant="h4"
                                        sx={{
                                          color: "black",
                                          pl: 5,
                                          fontSize: "1.25rem",
                                        }}
                                      >
                                        {otCount}
                                      </Typography>
                                    </Stack>
                                  </Stack>
                                </Paper>
                              </Grid>
                              <Grid item xs={6}>
                                <Paper
                                  elevation={6}
                                  sx={{
                                    p: 2,
                                    display: "flex",
                                    flexDirection: "column",
                                    height: 160,
                                  }}
                                >
                                  <Typography component="span" variant="h5"
                                              sx={{ color: "black" }}>
                                    NetView
                                  </Typography>
                                  <Button
                                    component="label"
                                    style={{
                                      padding: "0rem",
                                      paddingTop: "0rem",
                                      height: "3.4rem",
                                      marginTop: "1.5rem",
                                    }}
                                    size="large"
                                    variant="contained"
                                    onClick={handleOpenDiagram}
                                  >
                                    View
                                  </Button>
                                </Paper>
                              </Grid>
                            </Grid>
                          </Grid>

                          <Grid item xs={6}>
                            <Paper
                              elevation={6}
                              sx={{
                                p: 2,
                                display: "flex",
                                flexDirection: "column",
                                height: 160,
                              }}
                            >
                              <Typography component="span" variant="h5"
                                          sx={{ color: "black" }}>
                                Search Asset
                              </Typography>
                              <Stack
                                direction={"row"}
                                justifyContent="space-evenly"
                                alignItems="center"
                                sx={{ mt: 3 }}
                                spacing={4}
                              >
                                <Autocomplete
                                  disablePortal
                                  id="combo-box-demo"
                                  options={vendorlist}
                                  sx={{ width: 300 }}
                                  renderInput={(params) =>
                                    <TextField {...params} label="Asset"/>}
                                />
                                <Button
                                  component="label"
                                  style={{
                                    padding: "1rem",
                                    paddingTop: "1rem",
                                    height: "3.4rem",
                                    marginTop: "0rem",
                                  }}
                                  sx={{
                                    color: "black",
                                    backgroundColor: "#05a82b",
                                    "&:hover": { backgroundColor: "#ccc50e" },
                                  }}
                                  size="small"
                                  color="success"
                                  variant="contained"
                                >
                                  Search
                                </Button>
                              </Stack>
                            </Paper>
                          </Grid>
                        </Grid>
                      </Grid>
                      <Grid item xs={6} width={"90vh"}>
                        <Paper
                          elevation={6}
                          sx={{
                            p: 2,
                            display: "flex",
                            flexDirection: "column",
                            height: 230,
                          }}
                        >
                          <Typography component="span" variant="h5"
                                      sx={{ color: "black" }}>
                            Filters
                          </Typography>
                          <Stack
                            direction={"row"}
                            justifyContent="space-evenly"
                            alignItems="center"
                            sx={{ mt: 3 }}
                            spacing={4}
                          >
                            <Autocomplete
                              disablePortal
                              onChange={(_, value) => {
                                if (value) {
                                  setAssetData((prevAssetData) =>
                                    prevAssetData.filter(
                                      (item) => item.MAC === value.label),
                                  );
                                } else {
                                  setAssetData(
                                    (prevAssetData) => prevAssetData);
                                }
                              }}
                              id="combo-box-demo"
                              options={maclist}
                              sx={{ width: 300 }}
                              renderInput={(params) => (
                                <TextField {...params} label="MAC Address"/>
                              )}
                            />
                            <Autocomplete
                              disablePortal
                              id="combo-box-demo"
                              options={iplist}
                              sx={{ width: 300 }}
                              renderInput={(params) => <TextField {...params}
                                                                  label="IP Address"/>}
                            />
                            <Autocomplete
                              disablePortal
                              id="combo-box-demo"
                              options={protocollist}
                              sx={{ width: 300 }}
                              renderInput={(params) => <TextField {...params}
                                                                  label="Protocol"/>}
                            />
                          </Stack>
                          <Stack
                            direction={"row"}
                            justifyContent="space-evenly"
                            alignItems="center"
                            sx={{ mt: 3 }}
                          >
                            <Button
                              component="label"
                              style={{
                                padding: "0.5rem",
                                paddingTop: "0.5rem",
                                height: "3rem",
                                marginTop: "0.3rem",
                              }}
                              size="small"
                              color="success"
                              variant="contained"
                            >
                              Apply Filters
                            </Button>
                          </Stack>
                        </Paper>
                      </Grid>
                    </Grid>
                  </Grid>

                  <Grid item xs={12}>
                    <Paper elevation={6} sx={{
                      p: 2,
                      display: "flex",
                      flexDirection: "column",
                    }}>
                      <Typography component="span" variant="h5"
                                  sx={{ color: "black" }}>
                        Assets Table
                      </Typography>
                      <Table size="small" sx={{ mt: 2 }}
                             style={{ border: "1rem" }}>
                        <TableHead>
                          <TableRow>
                            <StyledTableCell sx={{ fontWeight: "bold" }}>
                              MAC Address
                            </StyledTableCell>

                            <StyledTableCell sx={{ fontWeight: "bold" }}
                                             align="center">
                              Vendor
                            </StyledTableCell>

                            <StyledTableCell sx={{ fontWeight: "bold" }}
                                             align="center">
                              IP Address
                            </StyledTableCell>
                            <StyledTableCell sx={{ fontWeight: "bold" }}
                                             align="center">
                              Protocol
                            </StyledTableCell>
                            <StyledTableCell sx={{ fontWeight: "bold" }}
                                             align="center">
                              Device Type
                            </StyledTableCell>

                            <StyledTableCell sx={{ fontWeight: "bold" }}
                                             align="center">
                              CVE Table
                            </StyledTableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {assetData?.map((row, index) => (
                            <StyledTableRow key={index}>
                              <StyledTableCell>{row.MAC}</StyledTableCell>
                              <StyledTableCell
                                align="center">{row.Vendor}</StyledTableCell>
                              <StyledTableCell
                                align="center">{row.IP}</StyledTableCell>
                              <StyledTableCell
                                align="center">{row.Protocol}</StyledTableCell>
                              <StyledTableCell
                                align="center">{row.device_type}</StyledTableCell>

                              <StyledTableCell align="center">
                                <IconButton
                                  color="primary"
                                  aria-label="upload picture"
                                  component="label"
                                  onClick={() => handleCVETable(row.MAC)}
                                >
                                  <OpenInNewIcon/>
                                </IconButton>
                              </StyledTableCell>
                            </StyledTableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </Paper>
                  </Grid>
                </Grid>
              </Container>
            )}
            <Dialog
              open={openGraph}
              onClose={handleCloseGraph}
              aria-labelledby="alert-dialog-title"
              aria-describedby="alert-dialog-description"
            >
              <DialogTitle id="alert-dialog-title">{"PCAP Upload"}</DialogTitle>
              <DialogContent>
                <Stack direction={"column"}>
                  {/* <Typography component="span" variant='h5' sx={{color: 'black'}}>
                    Asset Identification
                  </Typography> */}

                  <Stack
                    direction={"row"}
                    justifyContent="space-evenly"
                    alignItems="center"
                    sx={{ mt: 3 }}
                    spacing={3}
                  >
                    <Stack direction={"row"} spacing={3}>
                      <TextField
                        sx={{ mt: 0.5 }}
                        id="filled-basic"
                        size="small"
                        label={fileLabel}
                        disabled
                        variant="filled"
                      />

                      {/* <Button
                            component="label"
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem"}}
                            sx={{color:'black',backgroundColor:'#e6de10',"&:hover": {backgroundColor: "#ccc50e" }}}
                            // disabled={!analysisdisabled}

                            size='small'
                            variant="contained"
                          >
                            Browse

                          </Button> */}
                    </Stack>
                    <Button
                      component="label"
                      style={{
                        padding: "0.5rem",
                        paddingTop: "0.5rem",
                        height: "3rem",
                        marginTop: "0.3rem",
                      }}
                      size="small"
                      color="success"
                      variant="contained"
                      // disabled={analysisdisabled}
                      // onClick={handleOpenLoading}
                    >
                      <input type="file" accept="*.*" hidden
                             onChange={handleFileUpload}/>
                      Analyse
                    </Button>
                    {spinnerloading && <CircularProgress/>}
                  </Stack>
                </Stack>
              </DialogContent>
              <DialogActions>
                {/* <Button onClick={handleCloseGraph}>Close</Button> */}
              </DialogActions>
            </Dialog>
          </Box>
        </Box>

        <Dialog open={openDiagram} onClose={handleCloseDiagram} fullWidth={true}
                maxWidth={"lg"}>
          <DialogTitle>Network Diagram</DialogTitle>
          <DialogContent>
            <div style={{ width: "72rem", height: "35rem" }}>
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
              >
                <Controls/>
                <Background color="#aaa" gap={8}/>
                <MiniMap style={minimapStyle} zoomable pannable/>
              </ReactFlow>
            </div>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseDiagram}>Close</Button>
          </DialogActions>
        </Dialog>

        <Dialog open={openLoading} onClose={handleCloseLoading} fullWidth={true}
                maxWidth={"sm"}>
          <DialogTitle>Analyzing PCAP...</DialogTitle>
          <DialogContent>
            <LinearProgressWithLabel value={progress}/>
          </DialogContent>
        </Dialog>

        <Dialog
          open={openCVETable}
          onClose={handleCloseCVETable}
          aria-labelledby="alert-dialog-title"
          aria-describedby="alert-dialog-description"
          fullWidth={true}
          maxWidth={"xl"}
        >
          <DialogTitle id="alert-dialog-title">{"CVE Table"}</DialogTitle>
          <DialogContent>
            <Table size="small" sx={{ mt: 2 }} style={{ border: "1rem" }}>
              <TableHead>
                <TableRow>
                  <StyledTableCell sx={{ fontWeight: "bold" }}>CVE
                    ID</StyledTableCell>

                  <StyledTableCell sx={{ fontWeight: "bold" }} align="left">
                    Description
                  </StyledTableCell>
                  <StyledTableCell sx={{ fontWeight: "bold" }} align="left">
                    CVSS Score
                  </StyledTableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {cveData?.map((row, index) => (
                  <StyledTableRow key={index}>
                    <StyledTableCell>{row.cve.CVE_data_meta.ID}</StyledTableCell>
                    <StyledTableCell align="left">
                      {row.cve.description.description_data[0].value}
                    </StyledTableCell>
                    <StyledTableCell>{row.impact.baseMetricV3.cvssV3.baseScore}</StyledTableCell>
                  </StyledTableRow>
                ))}
              </TableBody>
            </Table>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseCVETable}>Close</Button>
          </DialogActions>
        </Dialog>

        <Snackbar open={openAlert} autoHideDuration={5000}
                  onClose={handleCloseAlert}>
          <Alert onClose={handleCloseAlert} severity="success"
                 sx={{ width: "100%" }}>
            PCAP File Uploaded!
          </Alert>
        </Snackbar>
      </ThemeProvider>
    </>
  );
}

export default App;
