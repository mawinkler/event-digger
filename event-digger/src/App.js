import React, { Component } from "react";
import './App.css';
import elasticsearch from "elasticsearch";

import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Paper from '@material-ui/core/Paper';


const client = new elasticsearch.Client({
  host: {
    protocol: 'http',
    host: '127.0.0.1',
    port: 9200
  },
  log: 'trace'
});

const es_index = "ws";

async function checkConnection() {
  let isConnected = false
  while (!isConnected) {
    console.log('Connecting to ES')
    try {
      const health = await client.cluster.health({})
      console.log(health)
      isConnected = true
    } catch (err) {
      console.log('Connection Failed, Retrying...', err)
    }
  }
}

class App extends Component {
  constructor(props) {
    super(props);

    this.state = { results: [] };
    // this.setState = this.setState.bind(this)
    this.handleChange = this.handleChange.bind(this)
  }

  handleChange(event) {
    const search_query = event.target.value;
    console.log("search_query: " + search_query)

    this.setState([])
    client.search({
      index: es_index,
      size: 100,

      body: {
        sort: [
          {"_id": {"order": "asc"}}
        ],
        query: {
          multi_match: {"query": search_query,
                        "fields": ["hostName", "target", "description", "malwareName", "infectedFilePath"],
                        "slop": 3,
                        "max_expansions": 100,
                        "type": "phrase_prefix"},
        },
      }
    })
      .then(
        function (body) {
          console.log("---LOG---");
          console.log(body);
          console.log("---LOG---");
          this.setState({ results: body.hits.hits });
        }.bind(this),
        function (error) {
          console.trace(error.message);
        }
      );
  }

  render() {
    checkConnection()
    return (
      <div className="App">
        <header className="App-header">
          <h1>Event Digger</h1>
          <div className="container">
            <input type="text" placeholder="Search..." onChange={this.handleChange} />
            <SearchResults results={this.state.results} />
          </div>
        </header>
      </div>
    );
  }
}

class SearchResults extends Component {
  render() {
    const results = this.props.results || [];

    return (
      <div className="search_results">
        <hr />
        {
          <TableContainer component={Paper}>
            <Table className="TABLE" aria-label="simple table">
              <TableHead>
                <TableRow>
                  <TableCell align="left">Time</TableCell>
                  <TableCell align="left">Event</TableCell>
                  <TableCell align="left">Target</TableCell>
                  <TableCell align="left">Malware Name</TableCell>
                  <TableCell align="left">Description or Path</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map(result => (
                  <TableRow>
                    <TableCell align="left">{new Date(result._source.timestamp * 1000).toLocaleString("en-US")}</TableCell>
                    <TableCell align="left">{result._source.event || result._source.scanType}</TableCell>
                    <TableCell align="left">{result._source.target || result._source.hostName}</TableCell>
                    <TableCell align="left">{"" || result._source.malwareName}</TableCell>
                    <TableCell align="left">{result._source.description || result._source.infectedFilePath}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        }
      </div>
    );
  }
}

export default App;
