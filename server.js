import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

app.get('/', (_req, res) => res.send('API OK'));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('API running on port ' + PORT));
