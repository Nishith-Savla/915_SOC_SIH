import * as React from 'react';
import { styled, createTheme, ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import httpClient from './httpClient';
import Dialog, { DialogProps } from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import { Link, useNavigate } from 'react-router-dom';

import { AppBar, Autocomplete, CircularProgress, LinearProgress, LinearProgressProps, Snackbar, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, duration, tableCellClasses } from '@mui/material';
import MuiAlert, { AlertProps } from '@mui/material/Alert';
import ParticleLinksWhite from './ParticleLinksWhite';
import dashboardlogo from '../public/industrial.png';

import ReactFlow, {
  addEdge,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
} from 'reactflow';

import 'reactflow/dist/style.css';
import './overview.css';
import { Title } from '@mui/icons-material';
import StaticGraph from './staticgraph';

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
  '&:nth-of-type(odd)': {
    backgroundColor: theme.palette.action.hover,
  },
  // hide last border
  '&:last-child td, &:last-child th': {
    border: 0,
  },
}));

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(function Alert(
  props,
  ref,
) {
  return <MuiAlert elevation={6} ref={ref} variant="filled" {...props} />;
});

function LinearProgressWithLabel(props: LinearProgressProps & { value: number }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center' }}>
      <Box sx={{ width: '100%', mr: 1 }}>
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

function App() {

  const [fileLabel, setfileLabel] = React.useState<any>('Upload File');


  const [openLoading, setOpenLoading] = React.useState(false);
  const [tabledisabled, setTableDisabled] = React.useState(true);
  // const [analysisdisabled, setAnalysisDisabled] = React.useState(true);


  const [progress, setProgress] = React.useState(10);

  const [openDiagram, setOpenDiagram] = React.useState(false);

  const [openAlert, setOpenAlert] = React.useState(false);
  
  const handleClickAlert = () => {
    setOpenAlert(true);
  };

  const handleCloseAlert = (event?: React.SyntheticEvent | Event, reason?: string) => {
    if (reason === 'clickaway') {
      return;
    }

    setOpenAlert(false);
  };
  

  const handleOpenLoading = () => {
    setOpenLoading(true);
    
    const timer = setInterval(() => {
      setProgress((prevProgress) => (prevProgress >= 100 ? (
        (() => {
          // Do something when the progress reaches 100
          clearInterval(timer);
          handleCloseLoading()
          // setAnalysisDisabled(false)
          setProgress(10)

        })(),
        100
      ) : prevProgress + 10));
    }, 800);
    
    return () => {
      clearInterval(timer);
    };
    
    
  }

  const handleCloseLoading = () => {
    setOpenLoading(false);
  }

  const handleOpenDiagram = () => {
    setOpenDiagram(true);

  }

  const handleCloseDiagram = () => {
    setOpenDiagram(false);
  }

  const handleCveTable = () =>{
    setTableDisabled(false);
  }
  const handleAssetsTable = () =>{
    setTableDisabled(true);
  }

  const protocolslist =[
    { label: 'HTTP' },
    { label: 'HTTPS' },
    { label: 'ModBus' },
    { label: 'DNP3' },
    { label: 'BacNet' },
  ]

  const sourcelist =[
    { label: '127.0.0.1' },
    { label: '127.0.0.2' },
    { label: '127.0.0.3' },
    
  ]
  const destlist =[
    { label: '127.0.0.1' },
    { label: '127.0.0.2' },
    { label: '127.0.0.3' },
    
  ]

  const handleFileUpload = async(e: any) => {
    const file = e.target.files[0];
    // console.log(file.name)

    if (file != null) {
      const data = new FormData();
      data.append('data', file);
  
      let response = await httpClient.post('//localhost:5000/upload',data
       
      );
      
      if (response.status == 200){
        handleClickAlert()
        setfileLabel(file.name)

      }
      else{
        alert('Error uploading file');
        setfileLabel("")

      }



    // handleClickAlert();

 
   
    }

  }

  const assetData = [
    { mac: '5c:88:16:ac:61:a9',vendor:'Rockwell Automation',devices:'array',count:'1',percentage:'3.2258' },
    { mac: 'd8:9e:f3:80:0f:8c',vendor:'Dell Inc',devices:'array',count:'1',percentage:'3.2258' },
    { mac: 'a4:5f:27:90:5e:94',vendor:'Scnider',devices:'array',count:'1',percentage:'4.2258' },

  ];

  const initialNodes = [
    { id: '1', position: { x: 0, y: 0 }, data: { label: '127.0.0.1' } },
    { id: '2', position: { x: 0, y: 100 }, data: { label: '127.0.0.2' } },
    { id: '3', position: { x: 200, y: 100 }, data: { label: '127.0.0.3' } },
  ];
  const initialEdges = [{ id: 'e1-2', source: '1', target: '2' },
  { id: 'e2-3', source: '2', target: '3' },
  ];

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);

  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

 

  return (
    <>
    <ParticleLinksWhite/> 
    
    <ThemeProvider theme={mdTheme}>
      <Box sx={{ display: 'flex', background: '#b0e2ff', opacity: '1' }} >
        <CssBaseline />
        <AppBar position="absolute"  sx={{background: '#026ced', height: '55px'}} >
          <Toolbar
            sx={{
              pr: '24px', // keep right padding when drawer closed
             
            }}
          >
            {/* <IconButton
              edge="start"
              color="inherit"
              aria-label="open drawer"
              onClick={toggleDrawer}
              sx={{
                marginRight: '36px',
                ...(open && { display: 'none' }),
              }}
            >
              <MenuIcon />
            </IconButton> */}
            <Typography
              component="h1"
              variant="h6"
              color="inherit"
              noWrap
              sx={{ flexGrow: 1 }}
            >
              Dashboard
            </Typography>

            <Typography
              component="h1"
              variant="h6"
              color="inherit"
              noWrap
              sx={{ flexGrow: -1 }}
            >
              <Button
        
        variant="outlined"
        sx={{color: 'white'}}
        component={Link} to="/kibana"
        // onClick={logout}
        // sx={{ marginRight: "1rem" }}
      >
      Log Analysis
        </Button>
            </Typography>
            
            <Typography
              component="h1"
              variant="h6"
              color="inherit"
              noWrap
              sx={{ flexGrow: -1 }}
            >
              <Button
        
        variant="outlined"
        sx={{color: 'white'}}
        component={Link} to="/"
        // onClick={logout}
        // sx={{ marginRight: "1rem" }}
      >
      Logout
        </Button>
            </Typography>
            
          </Toolbar>
        </AppBar>
      
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            height: '100vh',
            overflow: 'auto',
          }}
        >
          <Toolbar />


          <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }} >
            <Grid container spacing={3}>

              <Grid item xs={4} >
                <Paper elevation={6}
                  sx={{
                    p: 2,
                    display: 'flex',
                    flexDirection: 'column',
                    height: 240,
                    
                  }}
                >
                  <Stack  
                    direction={'column'}>
                  
                    <Typography component="span" variant='h5' sx={{color: 'black'}}>
                    Asset Identification
                  </Typography>
              
                        <Stack  
                          direction={'row'}
                          justifyContent="space-evenly"
                          alignItems="center"
                          sx={{mt:3}}
                          spacing={2} >
                            <Stack  
                          direction={'row'}
                          spacing={2}
                          >
                            <TextField sx={{mt:0.5}}id="filled-basic" size="small"  label={fileLabel} disabled variant="filled" />
                            
                            <Button
                            component="label"
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem"}}
                            sx={{color:'black',backgroundColor:'#e6de10',"&:hover": {backgroundColor: "#ccc50e" }}}
                            // disabled={!analysisdisabled}

                            size='small'
                            variant="contained"
                          >
                            Browse
                            <input type="file" accept=".pcap" hidden onChange={handleFileUpload} />

                          </Button>
                          </Stack>
                          <Button
                            component="label"
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem"}}
                            size='small'
                            color='success'
                            variant="contained"
                            // disabled={analysisdisabled}
                            onClick={handleOpenLoading}
                          >
                            Analyse
                          </Button>
                          
                          
                          </Stack>
                          <Stack  
                          direction={'row'}
                          justifyContent="space-evenly"
                          alignItems="center"
                          sx={{mt:3}}
                          spacing={4} >
                            
                           


                          <Button
                            component="label"
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem"}}
                            size='small'
                            variant="contained"
                            onClick={handleOpenDiagram}

                          >
                            Network Diagram
                          </Button>

                          
                          
                          </Stack>
                    </Stack>
    
                </Paper>
              </Grid>
              <Grid item xs={3} >
                <Paper elevation={6}
                  sx={{
                    p: 2,
                    display: 'flex',
                    flexDirection: 'column',
                    height: 240,
                  }}
                >
                <Typography component="span" variant='h5' sx={{color: 'black'}}>
                    Vulnerability Analysis
                  </Typography>
                  <Stack  
                          direction={'row'}
                          justifyContent="space-evenly"
                          alignItems="center"
                          sx={{mt:3}}
                          spacing={4} >
                  <Autocomplete
                  disablePortal
                  id="combo-box-demo"
                  options={protocolslist}
                  sx={{ width: 300 }}
                  renderInput={(params) => <TextField {...params} label="Asset" />}
                />
                <Button
                  component="label"
                  style={{padding:"1rem",paddingTop:"0.5rem",height:"3.4rem",marginTop:"0rem"}}
                  sx={{color:'black',backgroundColor:'#e6de10',"&:hover": {backgroundColor: "#ccc50e" }}}

                  size='small'
                  color='success'
                  variant="contained"
                >
                  Search
                </Button>
                </Stack>
              </Paper>
              </Grid>

              <Grid item xs={5} >
                <Paper elevation={6}
                  sx={{
                    p: 2,
                    display: 'flex',
                    flexDirection: 'column',
                    height: 240,
                  }}
                >
                  <Typography component="span" variant='h5' sx={{color: 'black'}}>
                    Filters
                  </Typography>
                  <Stack  
                          direction={'row'}
                          justifyContent="space-evenly"
                          alignItems="center"
                          sx={{mt:3}}
                          spacing={4} >
                <Autocomplete
                  disablePortal
                  id="combo-box-demo"
                  options={protocolslist}
                  sx={{ width: 300 }}
                  renderInput={(params) => <TextField {...params} label="Protocol" />}
                />
                <Autocomplete
                  disablePortal
                  id="combo-box-demo"
                  options={sourcelist}
                  sx={{ width: 300 }}
                  renderInput={(params) => <TextField {...params} label="Source" />}
                />
                <Autocomplete
                  disablePortal
                  id="combo-box-demo"
                  options={destlist}
                  sx={{ width: 300 }}
                  renderInput={(params) => <TextField {...params} label="Destination" />}
                />
                  </Stack>
                  <Stack  
                          direction={'row'}
                          justifyContent="space-evenly"
                          alignItems="center"
                          sx={{mt:3}}
                           >
                            <Stack 
                            direction={'row'}>
                            <Button
                            component="label"
                            disabled={tabledisabled}
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem",borderRadius:'0rem'}}
                            size='small'
                            variant="contained"
                            onClick={handleAssetsTable}
                          >
                            Assets Table
                          </Button>
                          <Button
                            component="label"
                            disabled={!tabledisabled}
                            onClick={handleCveTable}
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem",borderRadius:'0rem'}}
                            size='small'
                            variant="contained"
                          >
                            CVE Table
                          </Button>
                          </Stack>
                        <Button
                            component="label"
                            style={{padding:"0.5rem",paddingTop:"0.5rem",height:"3rem",marginTop:"0.3rem"}}
                            size='small'
                            color='success'
                            variant="contained"
                          >
                            Apply Filters
                          </Button>

                          
                          </Stack>
                  
                </Paper>
              </Grid>
              <Grid item xs={12} >
                <Paper elevation={6} sx={{ p: 2, display: 'flex', flexDirection: 'column' }}>
                {/* <Title>Cases</Title> */}
                <Typography component="span" variant='h5' sx={{color: 'black'}}>
                    Assets Table
                  </Typography>
                  <Table size="small" sx={{mt:2}} style={{border:"1rem"}}>
                    <TableHead>
                      <TableRow>
                        <StyledTableCell sx={{fontWeight: 'bold'}}>MAC Address</StyledTableCell>

                        <StyledTableCell sx={{fontWeight: 'bold'}} align="center">Vendor</StyledTableCell>

                        <StyledTableCell  sx={{fontWeight: 'bold'}} align="center">Devices</StyledTableCell>
                        <StyledTableCell  sx={{fontWeight: 'bold'}} align="center">Count</StyledTableCell>
                        <StyledTableCell  sx={{fontWeight: 'bold'}} align="center">Percentage</StyledTableCell>


                        {/* <StyledTableCell  sx={{fontWeight: 'bold'}} align="right">Delete Case</StyledTableCell> */}

                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {assetData?.map((row:any,index:any) => (
                        <StyledTableRow key={index}>

                          <StyledTableCell>{row.mac}</StyledTableCell>
                          <StyledTableCell align="center">{row.vendor}</StyledTableCell>
                          <StyledTableCell align="center">{row.devices}</StyledTableCell>
                          <StyledTableCell align="center">{row.count}</StyledTableCell>

                          <StyledTableCell align="center">{row.percentage}</StyledTableCell>



                        </StyledTableRow>
                      ))}
                    </TableBody>
                  </Table>
                
                
              
                </Paper>
              </Grid>
            </Grid>
          </Container>

        </Box>
      </Box>

      <Dialog open={openDiagram} onClose={handleCloseDiagram} 
      fullWidth={true}
      // fullHeight={fullHeight}
      maxWidth={'lg'}>
      
        <DialogTitle>Network Diagram</DialogTitle>
        <DialogContent>
          {/* <DialogContentText
            sx={{pb:2}}
            >
            
          </DialogContentText> */}
          <div style={{ width: '72rem', height: '35rem' }}>
                <ReactFlow 
                nodes={nodes} 
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange} 
                > 
                <Controls />
                <Background color="#aaa" gap={8} />
                <MiniMap style={minimapStyle} zoomable pannable />
                </ReactFlow>
                {/* <StaticGraph/> */}
                </div>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDiagram}>Close</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={openLoading} onClose={handleCloseLoading} 
      fullWidth={true}
      // fullHeight={fullHeight}
      maxWidth={'sm'}>
      
        <DialogTitle>Analyzing PCAP...</DialogTitle>
        <DialogContent>
          <LinearProgressWithLabel value={progress} />
        </DialogContent>
        
      </Dialog>


      <Snackbar open={openAlert} autoHideDuration={5000} onClose={handleCloseAlert} >
        <Alert onClose={handleCloseAlert} severity="success" sx={{ width: '100%' }} >
          PCAP File Uploaded!
        </Alert>
      </Snackbar>

    </ThemeProvider>
    </>

  );
}


export default App;


